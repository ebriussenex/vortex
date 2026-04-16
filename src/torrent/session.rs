use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, bail};

use percent_encoding::NON_ALPHANUMERIC;
use rand::distr::{Alphanumeric, SampleString};

use crate::{
    encoding::bencode::{Bencoded, decode_single},
    torrent::{announce::Announce, metadata::Torrent},
};

#[non_exhaustive]
#[derive(Debug, Clone)]
struct RequestEvent {}
//
//impl RequestEvent {
//    pub const STARTED: &str = "started";
//    pub const COMPLETED: &str = "completed";
//    pub const STOPPED: &str = "stopped";
//    pub const EMPTY: &str = "";
//}

type PeerId = [u8; 20];

#[derive(Debug, Clone)]
pub struct TrackerGetRequest {
    /// sha1 of bencoded info dictionary from .torrent file
    info_hash: [u8; 20],
    /// Client unique identifier, a string of len 20, generate random at start of a new download
    peer_id: PeerId,
    /// Optional parameter giving the IP (or DNS name) which this peer is at.
    /// Generally used for the origin if it's on the same machine as the tracker.
    ip: Option<String>,
    /// Port client listens to. Usually for downloader to try to listen
    /// on port `6881` and if that port is taken try `6882`, then `6883`,
    /// etc. and give up after `6889`
    port: u16,
    /// Bytes uploaded so far. Encoded in base ten ascii.
    uploaded: usize,
    /// Bytes downloaded so far. Encoded in base ten ascii.
    downloaded: usize,
    /// Number of bytes left to download. Encoded in base ten ascii.
    /// This can't be computed from downloaded and the file length,
    /// if some of the downloaded data failed an integrity check and
    /// had to be redownloaded.
    left: usize,
    /// Whether the peer list should use the compact representation. (0/1 val).
    /// Most of the time compact repr is used, keeping this for backward compatibility.
    compact: u8,
    /// This is an optional key which maps to started, completed, or stopped
    /// (or empty, which is the same as not being present). If not present,
    /// this is one of the announcements done at regular intervals.
    /// An announcement using started is sent when a download first begins,
    /// and one using completed is sent when the download is complete.
    /// No completed is sent if the file was complete when started.
    /// Downloaders send an announcement using stopped when they cease downloading.
    event: Option<String>,
}

/// Tracker response is bencoded dict.
#[derive(Debug, Clone)]
pub struct TrackerResponse {
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Peer {
    Compact(Ipv4Addr, u16),
    NonCompact(PeerId, SocketOrDomain),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SocketOrDomain {
    Socket(SocketAddr),
    Domain(String),
}

impl TrackerResponse {
    fn parse(response: &[u8]) -> anyhow::Result<Self> {
        let response_dict = decode_single(response)
            .context("decode response error")?
            .extract_dict()
            .context("content not bencoded dict")?;

        let interval = response_dict
            .get(b"interval".as_slice())
            .context("should contain interval")?
            .extract_int()
            .context("interval must be int type")?
            .try_into()
            .context("interval must be positive")?;

        let min_interval = response_dict
            .get(b"min interval".as_slice())
            .map(|v| {
                v.extract_int()
                    .context("min interval must be int")?
                    .try_into()
                    .context("min interval must be positive")
            })
            .transpose()?;

        let peers_bytes = response_dict
            .get(b"peers".as_slice())
            .context("should contain peers")?;

        let peers = Self::parse_peers(peers_bytes)?;
        Ok(TrackerResponse {
            min_interval,
            interval,
            peers,
        })
    }

    fn parse_peers(peers_bytes: &Bencoded) -> anyhow::Result<Vec<Peer>> {
        match peers_bytes {
            Bencoded::ByteStr(pb) => {
                if pb.len() % 6 != 0 {
                    bail!("unexpected peers len {}", pb.len());
                }
                pb.chunks_exact(6)
                    .map(|chunk| {
                        let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                        Ok(Peer::Compact(ip, port))
                    })
                    .collect::<Result<Vec<_>, _>>()
            }

            Bencoded::List(peers_list) => peers_list
                .iter()
                .map(|peer| {
                    let peer_dict = peer.extract_dict().context("peer in list should be dict")?;

                    let peer_id = peer_dict
                        .get(b"peer id".as_slice())
                        .context("peer missing peer id key")?
                        .extract_bytestr()
                        .context("peer id must be bytestring")?;

                    anyhow::ensure!(peer_id.len() == 20, "peer id is not 20 bytes long");

                    let peer_id: [u8; 20] = peer_id
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("(err) peer id must be exactly 20 bytes"))?;

                    let ip = &peer_dict
                        .get(b"ip".as_slice())
                        .context("peer missing ip key")?
                        .extract_bytestr()
                        .context("ip must be bytestring")?;

                    let ip = std::str::from_utf8(ip).context("ip invalid utf-8")?;

                    let port_i64 = peer_dict
                        .get(b"port".as_slice())
                        .context("peer missing port")?
                        .extract_int()
                        .context("port must be int")?;

                    let port = u16::try_from(port_i64)
                        .with_context(|| format!("port is out of range for u16: {}", port_i64))?;

                    let socket_or_domain = match format!("{}:{}", ip, port).parse::<SocketAddr>() {
                        Ok(socket) => SocketOrDomain::Socket(socket),
                        Err(_) => SocketOrDomain::Domain(ip.to_string()),
                    };

                    Ok(Peer::NonCompact(peer_id, socket_or_domain))
                })
                .collect::<Result<Vec<_>, _>>(),
            _ => bail!("peers should be bytestr (compact) or list"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrackerErrorResponse {
    failure_reason: String,
}

pub struct TorrentSession {
    peer_id: [u8; 20],
    ip: Option<String>,
    port: u16,

    downloaded: usize,
    uploaded: usize,
    left: usize,

    event: Option<String>,
    compact_mode: bool,

    /// Num of peers, wanted from tracker
    numwant: u16,

    info_hash: [u8; 20],

    client: reqwest::Client,

    announce: Announce,
}

struct GetQueryParams<'a> {
    info_hash: &'a [u8],
    peer_id: &'a [u8; 20],
    port: u16,
    uploaded: usize,
    downloaded: usize,
    left: usize,
    numwant: u16,
    compact_mode: bool,
    event: Option<&'a str>,
    ip: Option<&'a str>,
}

impl GetQueryParams<'_> {
    fn apply_to(&self, mut url: url::Url) -> url::Url {
        url.query_pairs_mut()
            .append_pair(
                "info_hash",
                &percent_encoding::percent_encode(self.info_hash, NON_ALPHANUMERIC).to_string(),
            )
            .append_pair("peer_id", str::from_utf8(self.peer_id).unwrap())
            .append_pair("port", &self.port.to_string())
            .append_pair("uploaded", &self.uploaded.to_string())
            .append_pair("downloaded", &self.downloaded.to_string())
            .append_pair("left", &self.left.to_string())
            .append_pair("numwant", &self.numwant.to_string())
            .append_pair("compact", if self.compact_mode { "1" } else { "0" });
        if let Some(event) = self.event {
            url.query_pairs_mut().append_pair("event", event);
        }
        if let Some(ip) = self.ip {
            url.query_pairs_mut().append_pair("ip", ip);
        }
        url
    }
}

impl TorrentSession {
    pub fn new(
        torrent_file: &Torrent,
        ip: Option<String>,
        port: u16,
        numwant: Option<u16>,
    ) -> Self {
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(Alphanumeric.sample_string(&mut rand::rng(), 20).as_bytes());

        TorrentSession {
            announce: Announce::new(
                torrent_file.announce_list.clone(),
                torrent_file.announce.clone(),
            ),
            peer_id,
            port,
            ip,

            downloaded: 0,
            uploaded: 0,
            left: torrent_file.total_size(),

            event: Some("started".to_string()),
            compact_mode: true,
            numwant: numwant.unwrap_or(80),

            info_hash: torrent_file.info_hash,

            client: reqwest::Client::new(),
        }
    }

    pub async fn request_peers_body(&mut self) -> anyhow::Result<Vec<u8>> {
        let params = GetQueryParams {
            info_hash: &self.info_hash,
            peer_id: &self.peer_id,
            port: self.port,
            uploaded: self.uploaded,
            downloaded: self.downloaded,
            left: self.left,
            numwant: self.numwant,
            compact_mode: self.compact_mode,
            event: self.event.as_deref(),
            ip: self.ip.as_deref(),
        };
        let client = &self.client;
        let mut src = self.announce.session();
        let mut last_err = anyhow::anyhow!("no trackers available");

        while let Some(tracker_url) = src.next() {
            let request_url = params.apply_to(tracker_url.clone());
            match client.get(request_url).send().await {
                Ok(resp) => {
                    let bytes = resp.bytes().await?.to_vec();
                    src.on_success();
                    return Ok(bytes);
                }
                Err(e) => {
                    eprintln!("tracker {tracker_url} failed: {e}");
                    last_err = e.into();
                }
            }
        }

        Err(last_err)
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

        let res = TrackerResponse::parse(&response).unwrap();

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

        let res = TrackerResponse::parse(response_bytes).unwrap();

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
