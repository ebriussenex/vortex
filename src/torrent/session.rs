use rand::distr::{Alphanumeric, SampleString};

use crate::torrent::{
    announce::Announce,
    metadata::Torrent,
    peer::{self, PeersResponse},
};
use thiserror::Error;

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

struct TrackerQueryParams<'a> {
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

impl TrackerQueryParams<'_> {
    fn apply_to(&self, mut url: url::Url) -> url::Url {
        url.query_pairs_mut()
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

        let encoded_hash: String = self
            .info_hash
            .iter()
            .map(|&b| format!("%{:02X}", b))
            .collect();
        let query = format!("{}&info_hash={}", url.query().unwrap_or(""), encoded_hash);
        url.set_query(Some(&query));
        url
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    Tracker(#[from] TrackerError),

    #[error("failed to request peers")]
    RequestPeers(#[from] peer::PeersResponseParseErr),
}
#[derive(Debug, Error)]
pub enum TrackerError {
    #[error("no trackers available")]
    NoTrackersAvailable,

    #[error("all trackers failed")]
    AllFailed(#[source] reqwest::Error),

    #[error("failed to read response body")]
    BodyRead(#[source] reqwest::Error),
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

    pub async fn request_peers_body(&mut self) -> Result<Vec<u8>, TrackerError> {
        let params = TrackerQueryParams {
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
        let mut last_err: Option<reqwest::Error> = None;

        while let Some(tracker_url) = src.next() {
            let request_url = params.apply_to(tracker_url.clone());
            match client.get(request_url).send().await {
                Ok(resp) => {
                    let bytes = resp.bytes().await.map_err(TrackerError::BodyRead)?.to_vec();
                    src.on_success();
                    return Ok(bytes);
                }
                Err(e) => {
                    eprintln!("tracker {tracker_url} failed: {e}");
                    last_err = Some(e);
                }
            }
        }

        Err(match last_err {
            Some(e) => TrackerError::AllFailed(e),
            None => TrackerError::NoTrackersAvailable,
        })
    }

    pub async fn start_session(&mut self) -> Result<(), SessionError> {
        let peers_body = self
            .request_peers_body()
            .await
            .map_err(SessionError::Tracker)?;

        let peers = PeersResponse::parse(&peers_body).map_err(SessionError::RequestPeers)?;

        println!("successfully got peers!");
        println!(
            "interval: {}, min_interval: {}, peers: {:?}",
            peers.interval,
            peers.min_interval.unwrap_or(0),
            peers.peers
        );

        Ok(())
    }
}
