use std::collections::BTreeMap;

pub enum DecodeErr {
    StrNotContainColon,
    TrailingData,
    UnexpectedFirstByte,
    EmptyInput,
    InvalidUtf8(std::str::Utf8Error),
    InvalidStrLen,
}

type ParseResult<'a, T> = Result<(T, &'a [u8]), DecodeErr>;

#[derive(Debug)]
pub enum Bencoded {
    Integer(i64),
    ByteStr(String),
    List(Vec<Bencoded>),
    Dict(BTreeMap<String, Bencoded>),
}

pub fn decode(input: &[u8]) -> ParseResult<'_, Bencoded> {
    let (val, rest) = parse_bencode(input)?;
    if !rest.is_empty() {
        Err(DecodeErr::TrailingData)
    } else {
        Ok((val, rest))
    }
}

fn parse_bencode(input: &[u8]) -> ParseResult<'_, Bencoded> {
    match input.first() {
        Some(b'0'..=b'9') => parse_bytestr(input),
        Some(_) => Err(DecodeErr::UnexpectedFirstByte),
        None => Err(DecodeErr::EmptyInput),
    }
}

fn parse_bytestr(input: &[u8]) -> ParseResult<'_, Bencoded> {
    let col_pos = input
        .iter()
        .position(|&b| b == b':')
        .ok_or(DecodeErr::StrNotContainColon)?;

    let strlen = std::str::from_utf8(&input[..col_pos])
        .map_err(DecodeErr::InvalidUtf8)?
        .parse::<usize>()
        .map_err(|_| DecodeErr::InvalidStrLen)?;

    let start = col_pos + 1;
    if input.len() < start + strlen {
        Err(DecodeErr::InvalidStrLen)
    } else {
        let str = std::str::from_utf8(&input[start..start + strlen])
            .map_err(DecodeErr::InvalidUtf8)?
            .to_string();
        Ok((Bencoded::ByteStr(str), &input[start + strlen..]))
    }
}
