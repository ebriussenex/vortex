use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use rand::distr::{Alphanumeric, SampleString};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinSet;
use tokio::time::interval;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::torrent::codec::{BittorrentCodec, Message};
use crate::torrent::peer::*;
use crate::torrent::piece::PieceManager;
use crate::torrent::{
    announce::Announce,
    metadata::Torrent,
    peer::{self, Handshake, PeersResponse},
};
use crate::utils::retry::retry_with_backoff;
use thiserror::Error;

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

    #[error("failed to request peers: {0}")]
    RequestPeers(#[source] peer::PeersResponseParseErr),

    #[error("peer connection error: {0}")]
    PeerConnErr(PeerConnErr),

    #[error("failed to write handshake: {0}")]
    HandshakeWrite(#[source] std::io::Error),

    #[error("failed to read handshake: {0}")]
    HandshakeRead(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum TrackerError {
    #[error("no trackers available")]
    NoTrackersAvailable,

    #[error("all trackers failed: {0}")]
    AllFailed(#[source] reqwest::Error),

    #[error("failed to read response body: {0}")]
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

    pub async fn start_session(&mut self) -> Result<StartedSession, SessionError> {
        let peers_body = self
            .request_peers_body()
            .await
            .map_err(SessionError::Tracker)?;

        let peers_resp = PeersResponse::parse(&peers_body).map_err(SessionError::RequestPeers)?;

        eprintln!("successfully got peers!");
        eprintln!(
            "interval: {}, min_interval: {}, peers: {:?}",
            peers_resp.interval,
            peers_resp.min_interval.unwrap_or(0),
            peers_resp.peers
        );

        // TODO: buffer size as configuration, 32 been taken from ceil
        let (tx, rx) = mpsc::channel::<(Arc<Peer>, TcpStream)>(32);
        let handshake = Arc::new(Handshake::new(&self.peer_id, &self.info_hash));

        eprintln!("starting handshake");

        let mut join_set = JoinSet::new();

        peers_resp.peers.into_iter().for_each(|peer| {
            let tx = tx.clone();
            let handshake = Arc::clone(&handshake);
            let peer = Arc::new(peer);
            join_set.spawn(async move {
                let conn_res: Result<TcpStream, PeerConnErr> =
                    retry_with_backoff(10, Duration::from_secs(1), || peer.connect(&handshake))
                        .await;
                match conn_res {
                    Ok(stream) => {
                        tx.send((peer, stream)).await.ok();
                    }
                    Err(e) => eprintln!("peer {peer:?} unreachable after retries: {e}"),
                }
            });
        });

        drop(tx);
        Ok(StartedSession { peer_streams: rx })
    }
}

struct StartedSession {
    peer_streams: Receiver<(Arc<Peer>, TcpStream)>,
}

type PeerSender = Sender<Message>;

impl StartedSession {
    async fn start_download(self) -> Result<(), SessionError> {
        let mut peers = self.peer_streams;
        let mut peer_senders: HashMap<Arc<Peer>, PeerSender> = HashMap::new();
        let mut join_set = JoinSet::new();

        loop {
            tokio::select! {
                Some((peer, stream)) = peers.recv() => {
                    let (tx, rx) = mpsc::channel::<Message>(32);
                    peer_senders.insert(Arc::clone(&peer), tx.clone());
                    join_set.spawn(peer_task(peer, stream, rx, tx));
                }

                Some(result) = join_set.join_next() => {
                    match result {
                        Ok(Err(e)) => eprintln!("peer task error: {e}"),
                        Err(e) => eprintln!("peer task panicked: {e}"),
                        Ok(Ok(())) => {}
                    }
                }
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerTaskErr {
    #[error("peer disconnected")]
    Disconnected,
    #[error("decode error: {0}")]
    Decode(std::io::Error),
    #[error("encode error: {0}")]
    Encode(std::io::Error),
}

async fn peer_task(
    peer: Arc<Peer>,
    stream: TcpStream,
    mut out_rx: Receiver<Message>,
    out_tx: Sender<Message>,
) -> Result<(), PeerTaskErr> {
    let mut framed = Framed::new(stream, BittorrentCodec {});
    let mut keepalive = interval(Duration::from_secs(120));
    let mut state = PeerState::new();

    // TODO: NOT CANCELATION SAFE FIX IT
    loop {
        tokio::select! {
            result = framed.next() => match result {
                None => return Err(PeerTaskErr::Disconnected),
                Some(Err(e)) => return Err(PeerTaskErr::Decode(e)),
                Some(Ok(msg)) => handle_msg(&peer, &msg, &out_tx, &mut state).await?,
            },
           Some(msg) = out_rx.recv() => {
                framed.send(msg).await.map_err(PeerTaskErr::Encode)?;
            },
            _ = keepalive.tick() => {
                framed.send(Message::KeepAlive).await.map_err(PeerTaskErr::Encode)?;
            },
        }
    }
}

async fn handle_msg(
    peer: &Arc<Peer>,
    msg: &Message,
    out: &mpsc::Sender<Message>,
    state: &mut PeerState,
) -> Result<(), PeerTaskErr> {
    match msg {
        Message::KeepAlive => {}
        Message::BitField(bitfield) => {
            // TODO: PieceManager should decide, about download from this peer, if there is
            // something to download. Yet always interested
            if !state.am_interested {
                state.am_interested = true;
                out.send(Message::Interested)
                    .await
                    .map_err(|_| PeerTaskErr::Disconnected)?;
            }
        }
        Message::Unchoke => {
            state.peer_choking = false;
            if state.can_download() {
                // TODO: request PieceManager next block and do request
            }
        }
        Message::Interested => {
            state.peer_interested = true;
        }
        Message::NotInterested => {
            state.peer_interested = false;
        }
        Message::Piece { index, begin, data } => {
            if !state.can_download() {
                // peer send us data, but we did not expected it
                eprintln!("peer {peer:?} sent piece while choked, ignoring");
            }
        }
        Message::Request { .. } | Message::Cancel { .. } => {
            if state.can_upload() {
                // TODO: load block from disk and send piece
            }
        }
        Message::Port(_port) => {
            // TODO: dht later
            unimplemented!()
        }
        Message::Choke => state.peer_choking = true,
        _ => {
            unimplemented!()
        }
    }
    Ok(())
}

struct PeerState {
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
}

impl PeerState {
    fn new() -> Self {
        Self {
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
        }
    }

    fn can_download(&self) -> bool {
        self.am_interested && !self.peer_choking
    }

    fn can_upload(&self) -> bool {
        !self.am_choking && self.peer_interested
    }
}
