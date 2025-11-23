use std::{collections::BTreeMap, io};

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
    ListNotContainEndTag,
    ListInvalidContent(Box<DecodeErr>),
    DictInvalidKey(Box<DecodeErr>),
    DictNotContainEndTag,
    DictInvalidValue(Box<DecodeErr>),
    DictNonUniqKey,
    IsNotDict,
    IsNotBytestr,
    IsNotList,
}

type ParseResult<'a, T> = Result<(T, &'a [u8]), DecodeErr>;

#[derive(Debug, PartialEq, Clone)]
pub enum Bencoded {
    Integer(i64),
    ByteStr(Vec<u8>),
    List(Vec<Bencoded>),
    Dict(BTreeMap<Vec<u8>, Bencoded>),
}

impl Bencoded {
    pub fn extract_dict(&self) -> Result<BTreeMap<Vec<u8>, Bencoded>, DecodeErr> {
        match self {
            Bencoded::Dict(dict) => Ok(dict.clone()),
            _ => Err(DecodeErr::IsNotDict),
        }
    }

    pub fn extract_bytestr(&self) -> Result<Vec<u8>, DecodeErr> {
        match self {
            Bencoded::ByteStr(bstr) => Ok(bstr.clone()),
            _ => Err(DecodeErr::IsNotBytestr),
        }
    }

    pub fn extract_int(&self) -> Result<i64, DecodeErr> {
        match self {
            Bencoded::Integer(n) => Ok(*n),
            _ => Err(DecodeErr::IsNotBytestr),
        }
    }

    pub fn extract_list(&self) -> Result<Vec<Bencoded>, DecodeErr> {
        match self {
            Bencoded::List(l) => Ok(l.to_vec()),
            _ => Err(DecodeErr::IsNotList),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, io::Error> {
        match self {
            Bencoded::Integer(num) => encode_int(*num),
            Bencoded::ByteStr(bstr) => encode_bytestr(bstr),
            Bencoded::List(items) => encode_list(items),
            Bencoded::Dict(dict) => encode_dict(dict),
        }
    }
}

fn encode_int(num: i64) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();

    buf.push(b'i');

    use std::io::Write;
    write!(&mut buf, "{}", num)?;

    buf.push(b'e');
    Ok(buf)
}

fn encode_bytestr(bstr: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();

    use std::io::Write;
    write!(&mut buf, "{}:", bstr.len())?;

    buf.extend_from_slice(bstr);

    Ok(buf)
}

fn encode_dict(dict: &BTreeMap<Vec<u8>, Bencoded>) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();

    buf.push(b'd');
    for (k, v) in dict {
        buf.extend_from_slice(&encode_bytestr(k)?);
        buf.extend_from_slice(&v.encode()?);
    }
    buf.push(b'e');

    Ok(buf)
}

fn encode_list(items: &Vec<Bencoded>) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();

    buf.push(b'l');
    items.iter().try_for_each(|it| {
        buf.extend_from_slice(&it.encode()?);
        Ok::<(), io::Error>(())
    })?;
    buf.push(b'e');

    Ok(buf)
}

pub fn decode_single(input: &[u8]) -> Result<Bencoded, DecodeErr> {
    let (val, rest) = parse_bencode(input)?;
    if !rest.is_empty() {
        eprintln!("decode_single: trailing data detected: {:?}", rest);
        eprintln!(
            "decode_single: input length: {}, consumed: {}",
            input.len(),
            input.len() - rest.len()
        );
        eprintln!(
            "decode_single: rest as UTF-8 (lossy): {:?}",
            std::str::from_utf8(rest)
        );
        return Err(DecodeErr::TrailingData);
    }
    Ok(val)
}

fn parse_bencode(input: &[u8]) -> ParseResult<'_, Bencoded> {
    match input.first() {
        Some(b'0'..=b'9') => parse_bytestr(input).map(|(val, rest)| (Bencoded::ByteStr(val), rest)),
        Some(b'i') => parse_int(input).map(|(val, rest)| (Bencoded::Integer(val), rest)),
        Some(b'l') => parse_list(input).map(|(val, rest)| (Bencoded::List(val), rest)),
        Some(b'd') => parse_dict(input).map(|(val, rest)| (Bencoded::Dict(val), rest)),
        Some(_) => Err(DecodeErr::UnexpectedFirstByte),
        None => Err(DecodeErr::EmptyInput),
    }
}

fn parse_dict(input: &[u8]) -> ParseResult<'_, BTreeMap<Vec<u8>, Bencoded>> {
    let mut res = BTreeMap::new();
    let mut rest = &input[1..];

    while !rest.starts_with(b"e") {
        if rest.is_empty() {
            return Err(DecodeErr::DictNotContainEndTag);
        }

        let (key, rest_after_key) =
            parse_bytestr(rest).map_err(|err| DecodeErr::DictInvalidKey(Box::new(err)))?;

        let (val, rest_after_val) = parse_bencode(rest_after_key)
            .map_err(|err| DecodeErr::DictInvalidValue(Box::new(err)))?;
        rest = rest_after_val;

        if res.contains_key(&key) {
            return Err(DecodeErr::DictNonUniqKey);
        }

        res.insert(key, val);
    }

    Ok((res, &rest[1..]))
}

fn parse_list(input: &[u8]) -> ParseResult<'_, Vec<Bencoded>> {
    let mut res = vec![];
    let mut rest = &input[1..];

    while !rest.starts_with(b"e") {
        if rest.is_empty() {
            return Err(DecodeErr::ListNotContainEndTag);
        }
        let (item, new_rest) =
            parse_bencode(rest).map_err(|err| DecodeErr::ListInvalidContent(Box::new(err)))?;
        res.push(item);
        rest = new_rest;
    }

    Ok((res, &rest[1..]))
}

fn parse_int(input: &[u8]) -> ParseResult<'_, i64> {
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
    Ok((bint, &input[e_pos + 1..]))
}

fn parse_bytestr(input: &[u8]) -> ParseResult<'_, Vec<u8>> {
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
        let str = &input[start..start + strlen].to_vec();
        Ok((str.to_owned(), &input[start + strlen..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // bytestr
    #[test]
    fn parse_valid_bytestr() {
        let input = b"4:spamrest";
        let (val, rest) = parse_bytestr(input).expect("should parse");
        assert_eq!(val, b"spam".to_vec());
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

    // int
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
            assert_eq!(val, expected.0);
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

    #[test]
    fn err_no_endtag_int() {
        assert_eq!(parse_int(b"i123"), Err(DecodeErr::IntNotContainEndTag));
    }

    #[test]
    fn err_invalid_int() {
        [&b"ie"[..], &b"ihhhhhe"[..]]
            .iter()
            .for_each(|input| assert_eq!(parse_int(input), Err(DecodeErr::InvalidInt)));
    }

    #[test]
    fn int_with_trailing() {
        let input = b"i32eextra";
        let (parsed, rest) = parse_int(input).unwrap();
        assert_eq!(parsed, 32);
        assert_eq!(rest, b"extra");
    }

    // list
    #[test]
    fn empty_list() {
        let input = b"le";
        let (val, rest) = parse_list(input).unwrap();
        assert_eq!(val, vec![]);
        assert_eq!(rest, b"");
    }

    #[test]
    fn list_with_integers() {
        let input = b"li1ei2ei3ee";
        let (val, rest) = parse_list(input).unwrap();
        assert_eq!(
            val,
            vec![
                Bencoded::Integer(1),
                Bencoded::Integer(2),
                Bencoded::Integer(3)
            ],
        );
        assert_eq!(rest, b"");
    }

    #[test]
    fn list_with_bytes() {
        let input = b"l4:spame";
        let (val, rest) = parse_list(input).unwrap();
        assert_eq!(val, vec![Bencoded::ByteStr(b"spam".to_vec())]);
        assert_eq!(rest, b"");
    }

    #[test]
    fn list_with_trailing_data() {
        let input = b"li1eeEXTRA";
        let (val, rest) = parse_list(input).unwrap();
        assert_eq!(val, vec![Bencoded::Integer(1)]);
        assert_eq!(rest, b"EXTRA");
    }

    #[test]
    fn list_missing_end_tag() {
        let input = b"li1e";
        let err = parse_list(input).unwrap_err();
        assert!(matches!(err, DecodeErr::ListNotContainEndTag));
    }

    #[test]
    fn list_invalid_content() {
        let input = b"l42e";
        let err = parse_list(input).unwrap_err();
        assert!(matches!(err, DecodeErr::ListInvalidContent(_)));
    }

    #[test]
    fn list_with_empty_lists() {
        let input = b"llelee";
        let (val, rest) = parse_list(input).expect("should parse");
        assert_eq!(val, vec![Bencoded::List(vec![]), Bencoded::List(vec![])]);
        assert_eq!(rest, b"");
    }

    #[test]
    fn list_complex_nested_structure() {
        let input = b"li42el5:inneri100eed3:key5:valueee";
        let (val, rest) = parse_list(input).unwrap();
        let mut dict = std::collections::BTreeMap::new();
        dict.insert(b"key".to_vec(), Bencoded::ByteStr(b"value".to_vec()));
        let expected = vec![
            Bencoded::Integer(42),
            Bencoded::List(vec![
                Bencoded::ByteStr(b"inner".to_vec()),
                Bencoded::Integer(100),
            ]),
            Bencoded::Dict(dict),
        ];
        assert_eq!(val, expected);
        assert_eq!(rest, b"");
    }

    #[test]
    fn list_with_inner_lists() {
        let input = b"ll23:http://bt3.t-ru.org/annel31:http://retracker.local/announceee";
        let (val, rest) = parse_list(input).unwrap();
        let expected = vec![
            Bencoded::List(vec![Bencoded::ByteStr(b"http://bt3.t-ru.org/ann".to_vec())]),
            Bencoded::List(vec![Bencoded::ByteStr(
                b"http://retracker.local/announce".to_vec(),
            )]),
        ];
        assert_eq!(val, expected);
        assert_eq!(rest, b"");
    }

    // dict
    #[test]
    fn empty_dict() {
        let input = b"de";
        let (dict, rest) = parse_dict(input).expect("should parse");
        assert!(dict.is_empty());
        assert_eq!(rest, b"");
    }

    #[test]
    fn simple_dict() {
        let input = b"d3:cow3:moo4:spam4:eggse";
        let (dict, rest) = parse_dict(input).unwrap();
        assert_eq!(dict.len(), 2);
        assert_eq!(
            dict.get(b"cow".as_slice()),
            Some(&Bencoded::ByteStr(b"moo".to_vec()))
        );
        assert_eq!(
            dict.get(b"spam".as_slice()),
            Some(&Bencoded::ByteStr(b"eggs".to_vec()))
        );
        assert_eq!(rest, b"");
    }

    #[test]
    fn dict_with_mixed_types() {
        let input = b"d4:name5:Alice3:agei30e5:adminl4:trueee";
        let (dict, rest) = parse_dict(input).expect("should parse");
        assert_eq!(
            dict.get(b"name".as_slice()),
            Some(&Bencoded::ByteStr(b"Alice".to_vec()))
        );
        assert_eq!(dict.get(b"age".as_slice()), Some(&Bencoded::Integer(30)));
        assert_eq!(
            dict.get(b"admin".as_slice()),
            Some(&Bencoded::List(vec![Bencoded::ByteStr(b"true".to_vec())]))
        );
        assert_eq!(rest, b"");
    }

    #[test]
    fn nested_dict() {
        let input = b"d5:outerd5:inner5:valueee";
        let (dict, rest) = parse_dict(input).expect("should parse");
        let inner = dict.get(b"outer".as_slice()).unwrap();
        match inner {
            Bencoded::Dict(inner_map) => {
                assert_eq!(
                    inner_map.get(&b"inner".to_vec()),
                    Some(&Bencoded::ByteStr(b"value".to_vec()))
                );
            }
            _ => panic!("Expected nested dict"),
        }
        assert_eq!(rest, b"");
    }

    #[test]
    fn dict_with_trailing_data() {
        let input = b"d3:key5:valueeTRAILING";
        let (dict, rest) = parse_dict(input).unwrap();
        assert_eq!(
            dict.get(b"key".as_slice()),
            Some(&Bencoded::ByteStr(b"value".to_vec()))
        );
        assert_eq!(rest, b"TRAILING");
    }

    #[test]
    fn dict_missing_end_tag() {
        let input = b"d3:key5:value";
        let err = parse_dict(input).unwrap_err();
        assert!(matches!(err, DecodeErr::DictNotContainEndTag));
    }

    #[test]
    fn dict_invalid_value() {
        let input = b"d3:key5:vale";
        let err = parse_dict(input).unwrap_err();
        assert!(matches!(err, DecodeErr::DictInvalidValue(_)));
    }

    #[test]
    fn dict_duplicate_key() {
        let input = b"d3:key4:val13:key4:val2e";
        let err = parse_dict(input).unwrap_err();
        assert!(matches!(err, DecodeErr::DictNonUniqKey));
    }

    #[test]
    fn dict_with_empty_key() {
        let input = b"d0:5:valuee";
        let (dict, rest) = parse_dict(input).unwrap();
        assert_eq!(
            dict.get(b"".as_slice()),
            Some(&Bencoded::ByteStr(b"value".to_vec()))
        );
        assert_eq!(rest, b"");
    }

    #[test]
    fn dict_with_inner_lists() {
        let input = b"d8:announce23:http://bt3.t-ru.org/ann13:announce-listll23:http://bt3.t-ru.org/annel31:http://retracker.local/announceeee";
        let (dict, rest) = parse_dict(input).unwrap();
        assert_eq!(
            dict.get(b"announce".as_slice()),
            Some(&Bencoded::ByteStr(b"http://bt3.t-ru.org/ann".to_vec()))
        );
        assert_eq!(
            dict.get(b"announce-list".as_slice()),
            Some(&Bencoded::List(vec![
                Bencoded::List(vec![Bencoded::ByteStr(b"http://bt3.t-ru.org/ann".to_vec())]),
                Bencoded::List(vec![Bencoded::ByteStr(
                    b"http://retracker.local/announce".to_vec()
                )]),
            ])),
        );

        assert_eq!(rest, b"");
    }

    // encode
    #[test]
    fn encoding_int() {
        let num: i64 = 1234795123;
        assert_eq!(encode_int(num).expect("expect to encode"), b"i1234795123e");
    }

    #[test]
    fn encoding_bytestr() {
        let bstr = b"hello";
        assert_eq!(
            encode_bytestr(bstr).expect("expected to encode"),
            b"5:hello"
        );
    }
}
