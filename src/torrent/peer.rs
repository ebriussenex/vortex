use std::{
    net::{Ipv4Addr, SocketAddr},
    str::Utf8Error,
};

use crate::encoding::bencode::{self, Bencoded, decode_single};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum PeersResponseParseErr {
    #[error("decoding response error")]
    Decoding(#[source] bencode::DecodeErr),
    #[error("response should contain interval")]
    NoInterval,
    #[error("interval must be positive")]
    NonPosInterval,
    #[error("interval must be integer")]
    NonIntInterval,
    #[error("min interval must be positive")]
    NonPosMinInterval,
    #[error("min interval must be integer")]
    NonIntMinInterval,
    #[error("should contain peers")]
    NoPeers,
    #[error("failed to parse peers")]
    PeersParseErr(#[source] PeersParseErr),
}

#[derive(Debug, Error)]
pub(crate) enum PeersParseErr {
    #[error("must be bencoded dict")]
    NotDict,
    #[error("missing peer id key")]
    NoPeerId,
    #[error("peer id not bytestr")]
    NotBytestr,
    #[error("peer id must be 20 bytes")]
    InvalidSize,
    #[error("missing ip key")]
    NoIPKey,
    #[error("ip must be bytestr")]
    NotBytestrIp,
    #[error("missing port")]
    NoPort,
    #[error("port must be int")]
    PortNotInt,
    #[error("port is out of range of u16")]
    PortOverflow,
    #[error("must be list or bytestr(compact)")]
    NotBytestrOrList,
    #[error("ip invalid utf-8")]
    IpInvalidUTF8(#[source] Utf8Error),
}

type PeerId = [u8; 20];

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Peer {
    Compact(Ipv4Addr, u16),
    NonCompact(PeerId, SocketOrDomain),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SocketOrDomain {
    Socket(SocketAddr),
    Domain(String),
}

/// Tracker response is bencoded dict.
#[derive(Debug, Clone)]
pub(crate) struct PeersResponse {
    /// Number of **seconds** the downloader should wait between regular rerequests
    pub interval: usize,
    /// Client should not announce more frequently then this
    pub min_interval: Option<usize>,
    /// A list of dictionaries corresponding to peers,
    /// each of which contains the keys peer id, ip, and port,
    /// which map to the peer's self-selected ID, IP address
    /// or dns name as a string, and port number, respectively.
    pub peers: Vec<Peer>,
}

impl PeersResponse {
    pub(crate) fn parse(response: &[u8]) -> Result<Self, PeersResponseParseErr> {
        let response_dict = decode_single(response)
            .map_err(PeersResponseParseErr::Decoding)?
            .extract_dict()
            .map_err(PeersResponseParseErr::Decoding)?;

        let interval = response_dict
            .get(b"interval".as_slice())
            .ok_or(PeersResponseParseErr::NoInterval)?
            .extract_int()
            .map_err(|_| PeersResponseParseErr::NonIntInterval)?
            .try_into()
            .map_err(|_| PeersResponseParseErr::NonPosInterval)?;

        let min_interval = response_dict
            .get(b"min interval".as_slice())
            .map(|v| {
                v.extract_int()
                    .map_err(|_| PeersResponseParseErr::NonIntMinInterval)?
                    .try_into()
                    .map_err(|_| PeersResponseParseErr::NonPosMinInterval)
            })
            .transpose()?;

        let peers_bytes = response_dict
            .get(b"peers".as_slice())
            .ok_or(PeersResponseParseErr::NoPeers)?;

        let peers = Self::parse_peers(peers_bytes).map_err(PeersResponseParseErr::PeersParseErr)?;

        Ok(PeersResponse {
            min_interval,
            interval,
            peers,
        })
    }

    fn parse_peers(peers_bytes: &Bencoded) -> Result<Vec<Peer>, PeersParseErr> {
        match peers_bytes {
            Bencoded::ByteStr(pb) => pb
                .chunks_exact(6)
                .map(|chunk| {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    Ok(Peer::Compact(ip, port))
                })
                .collect::<Result<Vec<_>, _>>(),
            Bencoded::List(peers_list) => peers_list
                .iter()
                .map(|peer| {
                    let peer_dict = peer.extract_dict().map_err(|_| PeersParseErr::NotDict)?;
                    let peer_id = peer_dict
                        .get(b"peer id".as_slice())
                        .ok_or(PeersParseErr::NoPeerId)?
                        .extract_bytestr()
                        .map_err(|_| PeersParseErr::NotBytestr)?;
                    if peer_id.len() != 20 {
                        return Err(PeersParseErr::InvalidSize);
                    }
                    let peer_id: [u8; 20] =
                        peer_id.try_into().map_err(|_| PeersParseErr::InvalidSize)?;
                    let ip = peer_dict
                        .get(b"ip".as_slice())
                        .ok_or(PeersParseErr::NoIPKey)?
                        .extract_bytestr()
                        .map_err(|_| PeersParseErr::NotBytestrIp)?;
                    let ip = std::str::from_utf8(&ip).map_err(PeersParseErr::IpInvalidUTF8)?;
                    let port_i64 = peer_dict
                        .get(b"port".as_slice())
                        .ok_or(PeersParseErr::NoPort)?
                        .extract_int()
                        .map_err(|_| PeersParseErr::PortNotInt)?;

                    let port = u16::try_from(port_i64).map_err(|_| PeersParseErr::PortOverflow)?;
                    let socket_or_domain = match format!("{}:{}", ip, port).parse::<SocketAddr>() {
                        Ok(socket) => SocketOrDomain::Socket(socket),
                        Err(_) => SocketOrDomain::Domain(ip.to_string()),
                    };
                    Ok(Peer::NonCompact(peer_id, socket_or_domain))
                })
                .collect::<Result<Vec<_>, _>>(),
            _ => Err(PeersParseErr::NotBytestrOrList),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;
    // tracker response parsing
    #[test]
    fn tracker_response_parsing_compact() {
        let peers_part = hex::decode("2e1637e8c8d5").unwrap();
        let ascii_res ="d8:completei0e10:downloadedi0e10:incompletei1e8:intervali1962e12:min intervali981e5:peers6:".as_bytes();
        let response = [ascii_res, &peers_part, b"e"].concat();

        let expected_ip = Ipv4Addr::from_str("46.22.55.232").unwrap();
        let expected_port = 51413;

        let res = PeersResponse::parse(&response).unwrap();

        assert_eq!(res.interval, 1962);
        assert_eq!(res.peers, vec![Peer::Compact(expected_ip, expected_port)]);
        assert_eq!(res.min_interval, Some(981));
    }

    #[test]
    fn tracker_response_parsing_non_compact() {
        let response_bytes = b"d8:intervali1800e5:peersld7:peer id20:012345678901234567892:ip12:46.22.55.2324:porti5141eeee";

        let expected_peer_id = *b"01234567890123456789";
        let expected_ip = Ipv4Addr::from_str("46.22.55.232").unwrap();
        let expected_port = 5141;

        let res = PeersResponse::parse(response_bytes).unwrap();

        assert_eq!(res.interval, 1800);
        assert_eq!(res.peers.len(), 1);

        if let Peer::NonCompact(peer_id, socket_or_domain) = &res.peers[0] {
            assert_eq!(*peer_id, expected_peer_id);

            match socket_or_domain {
                SocketOrDomain::Socket(addr) => {
                    assert_eq!(addr.ip(), expected_ip);
                    assert_eq!(addr.port(), expected_port);
                }
                SocketOrDomain::Domain(_) => panic!("got domain"),
            }
        } else {
            panic!("got compact");
        }
    }
}
