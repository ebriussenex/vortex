use std::io::ErrorKind;

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    BitField(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port(u16),
}

pub(crate) struct BittorrentCodec {}

const MAX_BLOCK_SIZE: usize = 1 << 14;
// TODO: this must be configurable. 1MB thou should be enough
const MAX_BITFIELD_SIZE: usize = 1 << 20;

impl Decoder for BittorrentCodec {
    type Item = Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_BLOCK_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            ));
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        src.advance(4);

        if length == 0 {
            return Ok(Some(Message::KeepAlive));
        }

        let data = src.split_to(length);

        let msg = match data[0] {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => Message::Have(read_u32(&data, 1)?),
            5 => Message::BitField(data[1..].to_vec()),
            6 => Message::Request {
                index: read_u32(&data, 1)?,
                begin: read_u32(&data, 5)?,
                length: read_u32(&data, 9)?,
            },
            7 => Message::Piece {
                index: read_u32(&data, 1)?,
                begin: read_u32(&data, 5)?,
                data: data[9..].to_vec(),
            },
            8 => Message::Cancel {
                index: read_u32(&data, 1)?,
                begin: read_u32(&data, 5)?,
                length: read_u32(&data, 9)?,
            },
            9 => Message::Port(read_u16(&data, 1)?),
            id => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("unknown message id: {id}"),
                ));
            }
        };
        Ok(Some(msg))
    }
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, std::io::Error> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "unexpected payload"))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, std::io::Error> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "unexpected payload"))
}

impl Encoder<Message> for BittorrentCodec {
    type Error = std::io::Error;
    fn encode(&mut self, msg: Message, dst: &mut BytesMut) -> Result<(), std::io::Error> {
        match msg {
            Message::KeepAlive => {
                dst.reserve(4);
                dst.put_u32(0);
            }
            Message::Choke => {
                dst.reserve(5);
                dst.put_u32(1);
                dst.put_u8(0);
            }
            Message::Unchoke => {
                dst.reserve(5);
                dst.put_u32(1);
                dst.put_u8(1);
            }
            Message::Interested => {
                dst.reserve(5);
                dst.put_u32(1);
                dst.put_u8(2);
            }
            Message::NotInterested => {
                dst.reserve(5);
                dst.put_u32(1);
                dst.put_u8(3);
            }
            Message::Have(index) => {
                dst.reserve(9);
                dst.put_u32(5);
                dst.put_u8(4);
                dst.put_u32(index);
            }
            Message::BitField(bitfield) => {
                if bitfield.len() > MAX_BITFIELD_SIZE {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("bitfield too large: {}", bitfield.len()),
                    ));
                }
                let len = 1 + bitfield.len();
                dst.reserve(4 + len);
                dst.put_u32(len as u32);
                dst.put_u8(5);
                dst.put_slice(&bitfield);
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                dst.reserve(17);
                dst.put_u32(13);
                dst.put_u8(6);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            Message::Piece { index, begin, data } => {
                if data.len() > MAX_BLOCK_SIZE {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("piece too large: {}", data.len()),
                    ));
                }
                let len = 9 + data.len();
                dst.reserve(4 + len);
                dst.put_u32(len as u32);
                dst.put_u8(7);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_slice(&data);
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                dst.reserve(17);
                dst.put_u32(13);
                dst.put_u8(8);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            Message::Port(port) => {
                dst.reserve(7);
                dst.put_u32(3);
                dst.put_u8(9);
                dst.put_u16(port);
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    fn encode_u32(val: u32) -> [u8; 4] {
        val.to_be_bytes()
    }

    fn make_frame(payload: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_u32(payload.len() as u32));
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_keepalive() {
        let mut dec = BittorrentCodec {};
        let mut buf = make_frame(&[]);
        let msg = dec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(msg, Message::KeepAlive));
    }

    #[test]
    fn test_choke() {
        let mut dec = BittorrentCodec {};
        let mut buf = make_frame(&[0]);
        assert!(matches!(
            dec.decode(&mut buf).unwrap().unwrap(),
            Message::Choke
        ));
    }

    #[test]
    fn test_have() {
        let mut dec = BittorrentCodec {};
        let mut buf = make_frame(&[4, 0, 0, 0, 42]);
        assert!(matches!(
            dec.decode(&mut buf).unwrap().unwrap(),
            Message::Have(42)
        ));
    }

    #[test]
    fn test_piece() {
        let mut dec = BittorrentCodec {};
        let data = b"hello";
        let mut payload = vec![7];
        payload.extend_from_slice(&encode_u32(1)); // index
        payload.extend_from_slice(&encode_u32(16)); // begin
        payload.extend_from_slice(data);
        let mut buf = make_frame(&payload);
        match dec.decode(&mut buf).unwrap().unwrap() {
            Message::Piece { index, begin, data } => {
                assert_eq!(index, 1);
                assert_eq!(begin, 16);
                assert_eq!(data, b"hello");
            }
            _ => panic!("expected Piece"),
        }
    }

    #[test]
    fn test_partial_frame_returns_none() {
        let mut dec = BittorrentCodec {};
        let mut buf = BytesMut::from(&encode_u32(10)[..]);
        assert!(dec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_too_large_frame() {
        let mut dec = BittorrentCodec {};
        let mut buf = BytesMut::from(&encode_u32((MAX_BLOCK_SIZE + 1) as u32)[..]);
        assert!(dec.decode(&mut buf).is_err());
    }

    #[test]
    fn test_unknown_id() {
        let mut dec = BittorrentCodec {};
        let mut buf = make_frame(&[99]);
        assert!(dec.decode(&mut buf).is_err());
    }

    #[test]
    fn test_two_frames_in_buffer() {
        let mut dec = BittorrentCodec {};
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&make_frame(&[0])); // Choke
        buf.extend_from_slice(&make_frame(&[1])); // Unchoke
        assert!(matches!(
            dec.decode(&mut buf).unwrap().unwrap(),
            Message::Choke
        ));
        assert!(matches!(
            dec.decode(&mut buf).unwrap().unwrap(),
            Message::Unchoke
        ));
    }

    fn roundtrip(msg: Message) -> Message {
        let mut codec = BittorrentCodec {};
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).expect("encode failed");
        codec
            .decode(&mut buf)
            .expect("decode failed")
            .expect("decode returned None")
    }

    #[test]
    fn test_keepalive_roundtrip() {
        assert!(matches!(roundtrip(Message::KeepAlive), Message::KeepAlive));
    }

    #[test]
    fn test_choke_roundtrip() {
        assert!(matches!(roundtrip(Message::Choke), Message::Choke));
    }

    #[test]
    fn test_unchoke_roundtrip() {
        assert!(matches!(roundtrip(Message::Unchoke), Message::Unchoke));
    }

    #[test]
    fn test_interested_roundtrip() {
        assert!(matches!(
            roundtrip(Message::Interested),
            Message::Interested
        ));
    }

    #[test]
    fn test_not_interested_roundtrip() {
        assert!(matches!(
            roundtrip(Message::NotInterested),
            Message::NotInterested
        ));
    }

    #[test]
    fn test_have_roundtrip() {
        match roundtrip(Message::Have(42)) {
            Message::Have(index) => assert_eq!(index, 42),
            _ => panic!("expected Have"),
        }
    }

    #[test]
    fn test_bitfield_roundtrip() {
        let bitfield = vec![0b11001010, 0b00110101];
        match roundtrip(Message::BitField(bitfield.clone())) {
            Message::BitField(b) => assert_eq!(b, bitfield),
            _ => panic!("expected BitField"),
        }
    }

    #[test]
    fn test_request_roundtrip() {
        match roundtrip(Message::Request {
            index: 1,
            begin: 0,
            length: MAX_BLOCK_SIZE as u32,
        }) {
            Message::Request {
                index,
                begin,
                length,
            } => {
                assert_eq!(index, 1);
                assert_eq!(begin, 0);
                assert_eq!(length, MAX_BLOCK_SIZE as u32);
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn test_piece_roundtrip() {
        let data = vec![1u8; 512];
        match roundtrip(Message::Piece {
            index: 3,
            begin: 128,
            data: data.clone(),
        }) {
            Message::Piece {
                index,
                begin,
                data: d,
            } => {
                assert_eq!(index, 3);
                assert_eq!(begin, 128);
                assert_eq!(d, data);
            }
            _ => panic!("expected Piece"),
        }
    }

    #[test]
    fn test_cancel_roundtrip() {
        match roundtrip(Message::Cancel {
            index: 2,
            begin: 0,
            length: 16384,
        }) {
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                assert_eq!(index, 2);
                assert_eq!(begin, 0);
                assert_eq!(length, 16384);
            }
            _ => panic!("expected Cancel"),
        }
    }

    #[test]
    fn test_port_roundtrip() {
        match roundtrip(Message::Port(6881)) {
            Message::Port(p) => assert_eq!(p, 6881),
            _ => panic!("expected Port"),
        }
    }

    #[test]
    fn test_piece_too_large() {
        let mut codec = BittorrentCodec {};
        let mut buf = BytesMut::new();
        let data = vec![0u8; MAX_BLOCK_SIZE + 1];
        assert!(
            codec
                .encode(
                    Message::Piece {
                        index: 0,
                        begin: 0,
                        data
                    },
                    &mut buf
                )
                .is_err()
        );
    }

    #[test]
    fn test_bitfield_too_large() {
        let mut codec = BittorrentCodec {};
        let mut buf = BytesMut::new();
        let bitfield = vec![0u8; MAX_BITFIELD_SIZE + 1];
        assert!(codec.encode(Message::BitField(bitfield), &mut buf).is_err());
    }

    #[test]
    fn test_reserve_no_realloc() {
        let mut codec = BittorrentCodec {};
        let mut buf = BytesMut::with_capacity(1024);
        let ptr_before = buf.as_ptr();
        codec.encode(Message::Have(1), &mut buf).unwrap();
        assert_eq!(buf.as_ptr(), ptr_before);
    }
}
