/*
 * paperback: paper backup generator suitable for long-term storage
 * Copyright (C) 2018-2022 Aleksa Sarai <cyphar@cyphar.com>
 * 
 * Modifications made in 2024 by YouXam <youxam@outlook.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::cmp::min;

use crate::{latest::Multihash, v0::{
    pdf::{Error, QRCODE_MULTIBASE},
    FromWire, ToWire, PAPERBACK_VERSION,
}};

use qrcode::QrCode;
use unsigned_varint::encode as varuint_encode;

use multihash_codetable::MultihashDigest;

const CHECKSUM_ALGORITHM: multihash_codetable::Code = multihash_codetable::Code::Blake2b256;
const CHECKSUM_MULTIBASE: multibase::Base = multibase::Base::Base32Z;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum PartType {
    MainDocumentData, // 'D'
}

impl ToWire for PartType {
    fn to_wire(&self) -> Vec<u8> {
        match self {
            Self::MainDocumentData => "D",
        }
        .into()
    }
}

impl FromWire for PartType {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        match input.split_first() {
            Some((b'D', input)) => Ok((input, Self::MainDocumentData)),
            None => Err("".into()), // TODO
            Some(_) => Err("".into()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PartMeta {
    version: u32,
    data_type: PartType,
    pub num_parts: usize,
}

impl ToWire for PartMeta {
    fn to_wire(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Encode version.
        bytes.extend_from_slice(varuint_encode::u32(
            self.version,
            &mut varuint_encode::u32_buffer(),
        ));

        // Encode data type.
        bytes.append(&mut self.data_type.to_wire());

        // Encode number of parts.
        bytes.extend_from_slice(varuint_encode::usize(
            self.num_parts,
            &mut varuint_encode::usize_buffer(),
        ));

        bytes
    }
}

impl FromWire for PartMeta {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use nom::{combinator::complete, IResult};
        use unsigned_varint::nom as varuint_nom;

        fn parse(input: &[u8]) -> IResult<&[u8], (u32, PartType, usize)> {
            let (input, version) = varuint_nom::u32(input)?;
            let (input, data_type) = PartType::from_wire_partial(input).unwrap(); // TODO TODO TODO
            let (input, num_parts) = varuint_nom::usize(input)?;

            Ok((input, (version, data_type, num_parts)))
        }
        let mut parse = complete(parse);

        let (input, (version, data_type, num_parts)) =
            parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((
            input,
            PartMeta {
                version,
                data_type,
                num_parts,
            },
        ))
    }
}

#[derive(Clone, Debug)]
pub struct Part {
    pub data: Vec<u8>,
    pub meta: PartMeta,
    pub part_idx: usize,
}

impl ToWire for Part {
    fn to_wire(&self) -> Vec<u8> {
        // Start with Pb prefix.
        let mut bytes = Vec::from(&b"Pb"[..]);

        // Encode metadata.
        bytes.append(&mut self.meta.to_wire());

        // Encode part index.
        bytes.extend_from_slice(varuint_encode::usize(
            self.part_idx,
            &mut varuint_encode::usize_buffer(),
        ));

        // Encode data.
        bytes.extend_from_slice(&self.data);

        bytes
    }
}

impl FromWire for Part {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use nom::{bytes::streaming::tag, combinator::complete, IResult};
        use unsigned_varint::nom as varuint_nom;

        fn parse(input: &[u8]) -> IResult<&[u8], (PartMeta, usize, Vec<u8>)> {
            let (input, _) = tag(b"Pb")(input)?;
            let (input, meta) = PartMeta::from_wire_partial(input).unwrap(); // TODO TODO TODO
            let (input, part_idx) = varuint_nom::usize(input)?;
            // TODO: Is this correct?
            let (input, data) = (&input[0..0], input.to_vec());

            Ok((input, (meta, part_idx, data)))
        }
        let mut parse = complete(parse);

        let (input, (meta, part_idx, data)) = parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((
            input,
            Part {
                meta,
                part_idx,
                data,
            },
        ))
    }
}

#[derive(Default, Debug)]
pub struct Page {
    pub len: usize,
    start_idx: usize,
    end_idx: usize,
    completed_parts: usize,
    pub page_number: usize,
    pub parts: [bool; 9]
}

impl Page {
    fn new(page_number: usize, start_idx: usize, end_idx: usize) -> Self {
        Self {
            len: end_idx - start_idx + 1,
            start_idx,
            end_idx,
            completed_parts: 0,
            page_number,
            parts: [false; 9],
        }
    }

    pub fn remaining(&self) -> usize {
        self.len - self.completed_parts
    }

    pub fn complete(&self) -> bool {
        self.len == self.completed_parts
    }

    fn add_part(&mut self, part_idx: usize) -> bool {
        if part_idx < self.start_idx || part_idx > self.end_idx {
            return false
        }
        let idx = part_idx - self.start_idx;
        if !self.parts[idx] {
            self.parts[idx] = true;
            self.completed_parts += 1;
            true
        } else {
            false
        }
    }

    pub fn remaining_parts(&self) -> Vec<usize> {
        (0..self.len)
            .filter(|idx| !self.parts[*idx])
            .map(|idx| idx + self.start_idx + 1)
            .collect()
    }

}
#[derive(Default, Debug)]
pub struct Joiner {
    meta: Option<PartMeta>,
    parts: Vec<Option<Part>>,
    pages: Vec<Page>,
    page_number: usize,
    completed_pages: usize,
}

impl Joiner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remaining(&self) -> Option<usize> {
        self.meta
            .map(|_| self.parts.iter().filter(|v| v.is_none()).count())
    }

    pub fn completed(&self) -> usize {
        self.parts.iter().filter(|v| v.is_some()).count()
    }

    pub fn complete(&self) -> bool {
        self.remaining() == Some(0)
    }

    pub fn add_part(&mut self, part: Part) -> Result<&Page, Error> {
        if let Some(meta) = self.meta {
            if meta != part.meta || part.part_idx >= meta.num_parts {
                return Err(Error::MismatchedQrCode);
            }
            if part.meta.version != PAPERBACK_VERSION {
                return Err(Error::WrongPaperbackVersion {
                    version: part.meta.version,
                });
            }
        } else {
            self.meta = Some(part.meta);
            self.parts = vec![None; part.meta.num_parts];

            self.page_number = (part.meta.num_parts - 1) / 9 + 1;
            self.pages = (0..self.page_number)
                .map(|idx| {
                    let start_idx = idx * 9;
                    let end_idx = min((idx + 1) * 9 - 1, part.meta.num_parts - 1);
                    Page::new(idx + 1, start_idx, end_idx)
                })
                .collect();
        }
        if part.part_idx >= self.parts.len() {
            return Err(Error::MismatchedQrCode);
        }
        let idx = part.part_idx;
        self.parts[idx] = Some(part);

        let page_idx = idx / 9;
        
        if self.pages[page_idx].add_part(idx) && self.pages[page_idx].complete() {
            self.completed_pages += 1;
        }

        Ok(&self.pages[page_idx])
    }

    pub fn combine_parts(&self) -> Result<Vec<u8>, Error> {
        let mut data_len = 0usize;
        for (idx, part) in self.parts.iter().enumerate() {
            if let Some(part) = part {
                data_len += part.data.len();
            } else {
                return Err(Error::MissingQrSegment { idx });
            }
        }
        let mut bytes = Vec::with_capacity(data_len);
        for part in self.parts.iter().flatten() {
            bytes.extend_from_slice(&part.data)
        }
        Ok(bytes)
    }

    pub fn remove_page(&mut self, page_number: usize) {
        let page_idx = page_number - 1;
        for idx in self.pages[page_idx].start_idx..=self.pages[page_idx].end_idx {
            self.parts[idx] = None;
        }
        self.pages[page_idx] = Page::new(
            page_number,
            self.pages[page_idx].start_idx,
            self.pages[page_idx].end_idx,
        );
    }

    pub fn checksum(&self, page_number: usize) -> Multihash {
        let page_idx = page_number - 1;
        let mut datas = Vec::new();
        for idx in self.pages[page_idx].start_idx..=self.pages[page_idx].end_idx {
            datas.extend_from_slice(self.parts[idx].as_ref().unwrap().data.as_slice());
        }
        CHECKSUM_ALGORITHM.digest(datas.as_ref())
    }

    pub fn checksum_string(&self, page_number: usize) -> String {
        multibase::encode(CHECKSUM_MULTIBASE, self.checksum(page_number).to_bytes())
    }
}

const DATA_OVERHEAD: usize = 1 /* multibase header */ +
                             1 /* (varuint) version = 0 */ +
                             1 /* data type */ +
                             2 * 9 /* 2*varuint length and index */;

// TODO: Make this dynamic based on the error correction mode.
const MAX_DATA_LENGTH: usize = 926 - DATA_OVERHEAD;

fn split_data<B: AsRef<[u8]>>(data_type: PartType, data: B) -> Vec<Part> {
    let data = data.as_ref();
    let chunks = data.chunks(MAX_DATA_LENGTH).collect::<Vec<_>>();
    chunks
        .iter()
        .enumerate()
        .map(|(idx, &chunk)| Part {
            meta: PartMeta {
                version: PAPERBACK_VERSION,
                data_type,
                num_parts: chunks.len(),
            },
            part_idx: idx,
            data: chunk.into(),
        })
        .collect()
}

pub(super) fn generate_codes<B: AsRef<[u8]>>(
    data_type: PartType,
    data: B,
) -> Result<(Vec<QrCode>, Vec<Vec<u8>>), Error> {
    let codes = split_data(data_type, data)
        .iter()
        .map(ToWire::to_wire)
        .collect::<Vec<_>>();
    Ok((
        codes
            .iter()
            .map(|data| multibase::encode(QRCODE_MULTIBASE, data))
            .map(QrCode::new)
            .collect::<Result<Vec<_>, _>>()?,
        codes,
    ))
}

pub(super) fn generate_one_code<B: AsRef<[u8]>>(data: B) -> Result<QrCode, Error> {
    // NOTE: We don't use a split code for single-QR-code data segments. The
    // reason for this is that the part header takes up space, and it also
    // causes checksums to be encoded differently (meaning that the document ID
    // would no longer be the last x characters of the hash).
    Ok(QrCode::new(multibase::encode(QRCODE_MULTIBASE, data))?)
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck::*;
    use rand::seq::SliceRandom;

    #[quickcheck]
    fn split_join_qr_parts(data: Vec<u8>) -> Result<bool, Error> {
        let mut parts = split_data(PartType::MainDocumentData, &data);
        let mut joiner = Joiner::new();

        parts.shuffle(&mut rand::thread_rng());
        for part in parts {
            joiner.add_part(part)?;
        }
        Ok(joiner.combine_parts()? == data)
    }
}
