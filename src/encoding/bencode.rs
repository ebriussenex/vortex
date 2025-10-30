use std::collections::BTreeMap;

#[derive(Debug, PartialEq)]
pub enum DecodeErr {
    StrNotContainColon,
    TrailingData,
    InvalidInt,
    LeadingZeroInt,
    NegativeZeroInt,
    IntNotContainEndTag,
    UnexpectedFirstByte,
    EmptyInput,
    InvalidUtf8(std::str::Utf8Error),
    InvalidStrLen,
}

type ParseResult<'a, T> = Result<(T, &'a [u8]), DecodeErr>;

#[derive(Debug, PartialEq)]
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
        Some(b'i') => parse_int(input),
        Some(_) => Err(DecodeErr::UnexpectedFirstByte),
        None => Err(DecodeErr::EmptyInput),
    }
}

fn parse_int(input: &[u8]) -> ParseResult<'_, Bencoded> {
    let e_pos = input
        .iter()
        .position(|&b| b == b'e')
        .ok_or(DecodeErr::IntNotContainEndTag)?;

    if input[..e_pos].len() < 2 {
        return Err(DecodeErr::InvalidInt);
    }

    if input[1..e_pos].len() > 1 && input[1] == b'0' {
        return Err(DecodeErr::LeadingZeroInt);
    }

    if input[1] == b'-' && input[2] == b'0' {
        if input[1..e_pos].len() > 2 {
            return Err(DecodeErr::LeadingZeroInt);
        }
        return Err(DecodeErr::NegativeZeroInt);
    }

    let bint = std::str::from_utf8(&input[1..e_pos])
        .map_err(DecodeErr::InvalidUtf8)?
        .parse::<i64>()
        .map_err(|_| DecodeErr::InvalidInt)?;
    Ok((Bencoded::Integer(bint), &input[e_pos + 1..]))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_bytestr() {
        let input = b"4:spamrest";
        let (val, rest) = parse_bytestr(input).expect("should parse");
        assert_eq!(val, Bencoded::ByteStr("spam".to_string()));
        assert_eq!(rest, b"rest");
    }

    #[test]
    fn err_bytestr_no_col() {
        let input = b"4spamrest";
        let res = parse_bytestr(input);
        assert_eq!(res, Err(DecodeErr::StrNotContainColon));
    }

    #[test]
    fn err_bytestr_no_content() {
        let input = b"4:";
        let res = parse_bytestr(input);
        assert_eq!(res, Err(DecodeErr::InvalidStrLen));
    }

    #[test]
    fn err_bytestr_badlen() {
        let input = b"5:spam";
        let res = parse_bytestr(input);
        assert_eq!(res, Err(DecodeErr::InvalidStrLen));
    }

    #[test]
    fn parse_valid_int() {
        let expected = [
            (12, &b"1:a"[..]),
            (-24, &b"4:sime"[..]),
            (-23, &b"some"[..]),
            (13, &b"i23e"[..]),
            (0, &b""[..]),
        ];
        [
            &b"i12e1:a"[..],
            &b"i-24e4:sime"[..],
            &b"i-23esome"[..],
            &b"i13ei23e"[..],
            &b"i0e"[..],
        ]
        .iter()
        .zip(expected.iter())
        .for_each(|(input, expected)| {
            let (val, rest) = parse_int(input).expect("should parse");
            assert_eq!(val, Bencoded::Integer(expected.0));
            assert!(
                rest == expected.1,
                "rest mismatch:\n  input: {:?}\n  got:   {:?}\n  want:  {:?}",
                String::from_utf8_lossy(input),
                String::from_utf8_lossy(rest),
                String::from_utf8_lossy(expected.1)
            );
        });
    }

    #[test]
    fn err_negzero_int() {
        assert_eq!(parse_int(b"i-0e"), Err(DecodeErr::NegativeZeroInt));
    }

    #[test]
    fn err_leadingzeroes_int() {
        [&b"i03e"[..], &b"i0003e"[..], &b"i-03e"[..]]
            .iter()
            .for_each(|input| {
                assert_eq!(parse_int(input), Err(DecodeErr::LeadingZeroInt));
            });
    }
}
