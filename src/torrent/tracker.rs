use percent_encoding::NON_ALPHANUMERIC;
use rand::distr::{Alphanumeric, SampleString};

use crate::torrent::metadata::Torrent;

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

#[derive(Debug, Clone)]
pub struct TrackerGetRequest {
    /// sha1 of bencoded info dictionary from .torrent file
    info_hash: [u8; 20],
    /// Client unique identifier, a string of len 20, generate random at start of a new download
    peer_id: [u8; 20],
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
    interval: usize,
    /// A list of dictionaries corresponding to peers,
    /// each of which contains the keys peer id, ip, and port,
    /// which map to the peer's self-selected ID, IP address
    /// or dns name as a string, and port number, respectively.
    peers: String,
}

#[derive(Debug, Clone)]
pub struct TrackerErrorResponse {
    failure_reason: String,
}

pub struct TorrentSession<'a> {
    peer_id: [u8; 20],
    ip: Option<String>,
    port: u16,
    torrent_file: &'a Torrent,

    downloaded: usize,
    uploaded: usize,
    left: usize,

    event: Option<String>,
    compact: u8,
}

impl<'a> TorrentSession<'a> {
    pub fn new(torrent_file: &'a Torrent, ip: Option<String>, port: u16) -> Self {
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(Alphanumeric.sample_string(&mut rand::rng(), 20).as_bytes());

        TorrentSession {
            torrent_file,
            peer_id,
            port,
            ip,

            downloaded: 0,
            uploaded: 0,
            left: torrent_file.total_size(),

            event: Some("started".to_string()),
            compact: 1,
        }
    }

    pub fn build_get_request(&self) -> url::Url {
        let mut url = self.torrent_file.announce.clone();
        url.query_pairs_mut()
            .append_pair(
                "info_hash",
                &percent_encoding::percent_encode(&self.torrent_file.info_hash, NON_ALPHANUMERIC)
                    .to_string(),
            )
            .append_pair(
                "peer_id",
                &percent_encoding::percent_encode(&self.peer_id, NON_ALPHANUMERIC).to_string(),
            )
            .append_pair("port", &self.port.to_string())
            .append_pair("uploaded", &self.uploaded.to_string())
            .append_pair("downloaded", &self.downloaded.to_string())
            .append_pair("left", &self.left.to_string())
            .append_pair("compact", &self.compact.to_string());
        if let Some(event) = &self.event {
            url.query_pairs_mut().append_pair("event", event);
        };
        if let Some(ip) = &self.ip {
            url.query_pairs_mut().append_pair("ip", ip);
        }
        url
    }
}
