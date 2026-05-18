use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::Arc,
    usize,
};

use bitvec::vec::BitVec;
use sha1::digest::typenum::Bit;
use thiserror::Error;
use tokio::time::Instant;

use crate::torrent::{peer::Peer, piece};

const BLOCK_SIZE: usize = 1 << 14;

#[derive(Debug, Error)]
pub(crate) enum PieceManagerErr {
    #[error("torrent file is empty")]
    Empty,
    #[error("pieces is empty. Vortex logic is wrong!")]
    EmptyPieces,
    #[error("given bitfield is empty")]
    EmptyBitfield,
    #[error("spare bits in bitfield must be zeroes")]
    SpareBitsNotZero,
    #[error("invalid block lenght")]
    InvalidBlockLength,
    #[error("invalid block index")]
    InvalidBlockIndex,
    #[error("piece index {0} out of range")]
    PieceIndexOutOfRange(usize),
    #[error("requested peer unkown")]
    UnknownPeer,
    #[error("invalid bitfield size: expected: {exp}, actual: {act}")]
    InvalidBitfieldSize { exp: usize, act: usize },
    #[error("file too large: {0}")]
    FileTooLarge(u64),
    #[error("overflow")]
    Overflow,
    #[error("block {block_idx} out of range for piece {piece_idx}")]
    BlockOutOfRange { block_idx: usize, piece_idx: usize },
    #[error("peer should send bitfield right after handshake and once")]
    BitfieldNotFirst,
    #[error("can only request missing blocks")]
    BlockNotMissing,
    #[error("can only recieve requested blocks")]
    BlockNotRequested,
    // TODO: it is logical, but seems little useless. think about it.
    #[error("peer received block which wasn't marked as required")]
    BlockNotRequestedFromPeer,
    #[error("marking incomplete piece as done, not all blocks received")]
    PieceIncomplete,
}

// TODO: Roaring bitmaps
pub(crate) struct PieceManager {
    own_bitfield: BitVec,

    pieces: Vec<PieceState>,
    blocks: Vec<Block>,

    peers: HashMap<PeerId, PeerState>,

    piece_hashes: Vec<[u8; 20]>,
    piece_size: usize,
    last_piece_size: usize,
    blocks_in_full_piece: usize,
}

#[derive(Clone)]
pub(crate) enum PieceState {
    Missing,
    InProgress,
    Done,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BlockId {
    pub piece: usize,
    pub index: usize,
}

// struct over 1 field is ok for future, too much code to rewrite
#[derive(Clone)]
pub struct Block {
    pub state: BlockState,
}

// TODO: state machine transition
#[derive(Clone)]
pub(crate) enum BlockState {
    Missing,
    Requested { at: Instant },
    Received,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct PeerId(pub usize);

// TODO: state machine transition
pub struct PeerState {
    pub bitfield: BitVec,
    pub in_flight: HashSet<BlockId>,
}

impl PieceManager {
    pub(crate) fn new(
        piece_hashes: Vec<[u8; 20]>,
        piece_size: usize,
        total_size: u64,
    ) -> Result<Self, PieceManagerErr> {
        if piece_hashes.is_empty() {
            return Err(PieceManagerErr::Empty);
        }

        let piece_size_u64 = piece_size as u64;
        let rem = total_size % piece_size_u64;
        let last_piece_size = if rem == 0 {
            piece_size
        } else {
            usize::try_from(rem).map_err(|_| PieceManagerErr::Overflow)?
        };

        let blocks_in_full_piece = piece_size.div_ceil(BLOCK_SIZE);
        let blocks_in_last_piece = last_piece_size.div_ceil(BLOCK_SIZE);
        let blocks = vec![
            Block {
                state: BlockState::Missing,
            };
            blocks_in_full_piece * (piece_hashes.len() - 1) + blocks_in_last_piece
        ];

        Ok(Self {
            own_bitfield: BitVec::repeat(false, piece_hashes.len()),
            pieces: vec![PieceState::Missing; piece_hashes.len()],
            piece_hashes,
            piece_size,
            last_piece_size,
            blocks,
            blocks_in_full_piece,
            peers: HashMap::new(),
        })
    }

    pub(crate) fn piece_size(&self, piece_idx: usize) -> Result<usize, PieceManagerErr> {
        if self.pieces.is_empty() {
            return Err(PieceManagerErr::EmptyPieces);
        }
        match piece_idx.cmp(&(self.pieces.len() - 1)) {
            Ordering::Greater => Err(PieceManagerErr::PieceIndexOutOfRange(piece_idx)),
            Ordering::Less => Ok(self.piece_size),
            Ordering::Equal => Ok(self.last_piece_size),
        }
    }

    pub(crate) fn blocks_in_piece(&self, piece_idx: usize) -> Result<usize, PieceManagerErr> {
        Ok(self.piece_size(piece_idx)?.div_ceil(BLOCK_SIZE))
    }

    pub(crate) fn block_size(
        &self,
        piece_idx: usize,
        block_idx: usize,
    ) -> Result<usize, PieceManagerErr> {
        let blocks_in_piece = self.blocks_in_piece(piece_idx)?;
        if block_idx >= blocks_in_piece {
            return Err(PieceManagerErr::BlockOutOfRange {
                block_idx,
                piece_idx,
            });
        }

        let piece_size = self.piece_size(piece_idx)?;
        let rem = piece_size % BLOCK_SIZE;
        let last_block_size = if rem == 0 { BLOCK_SIZE } else { rem };

        if block_idx == blocks_in_piece - 1 {
            Ok(last_block_size)
        } else {
            Ok(BLOCK_SIZE)
        }
    }

    pub(crate) fn update_peer_bitfield(
        &mut self,
        peer: PeerId,
        bitfield: BitVec,
    ) -> Result<(), PieceManagerErr> {
        if self.peers.contains_key(&peer) {
            return Err(PieceManagerErr::BitfieldNotFirst);
        }
        if bitfield.len() != self.pieces.len() {
            return Err(PieceManagerErr::InvalidBitfieldSize {
                exp: self.pieces.len(),
                act: bitfield.len(),
            });
        }

        self.peers.insert(
            peer,
            PeerState {
                bitfield,
                in_flight: HashSet::new(),
            },
        );

        Ok(())
    }

    pub(crate) fn update_peer_have(
        &mut self,
        peer: &PeerId,
        piece_idx: usize,
    ) -> Result<(), PieceManagerErr> {
        if piece_idx >= self.pieces.len() {
            return Err(PieceManagerErr::PieceIndexOutOfRange(piece_idx));
        }

        let peer_state = self.peers.entry(peer.clone()).or_insert_with(|| PeerState {
            bitfield: BitVec::repeat(false, self.pieces.len()),
            in_flight: HashSet::new(),
        });

        peer_state.bitfield.set(piece_idx, true);
        Ok(())
    }

    pub(crate) fn peer_has_piece(
        &self,
        peer: &PeerId,
        piece_idx: usize,
    ) -> Result<bool, PieceManagerErr> {
        let peer = self.peers.get(peer).ok_or(PieceManagerErr::UnknownPeer)?;
        // second case should NEVER happen until bitfield creation is broken
        if piece_idx >= self.pieces.len() || peer.bitfield.len() <= piece_idx {
            return Err(PieceManagerErr::PieceIndexOutOfRange(piece_idx));
        }

        Ok(peer.bitfield[piece_idx])
    }

    pub(crate) fn select_piece(&self, peer: &PeerId) -> Option<usize> {
        let peer_state = self.peers.get(peer)?;
        self.pieces.iter().enumerate().find_map(|(i, piece)| {
            if !matches!(piece, PieceState::Missing) {
                return None;
            }
            if !peer_state.bitfield.get(i).is_some_and(|b| *b) {
                return None;
            }
            Some(i)
        })
    }

    pub(crate) fn select_block(&self, piece_idx: usize) -> Option<BlockId> {
        let blocks_in_piece = self.blocks_in_piece(piece_idx).ok()?;
        for block_idx in 0..blocks_in_piece {
            let global_block_idx = self.global_block_idx(piece_idx, block_idx);
            let block = self.blocks.get(global_block_idx)?;
            if matches!(block.state, BlockState::Missing) {
                return Some(BlockId {
                    piece: piece_idx,
                    index: block_idx,
                });
            }
        }
        None
    }

    pub(crate) fn release_peer(&mut self, peer: &PeerId) {
        let Some(peer_state) = self.peers.remove(peer) else {
            return;
        };
        let mut affected_pieces = HashSet::new();

        for block_id in peer_state.in_flight {
            let block_idx = block_id.index;
            let piece_idx = block_id.piece;

            let global_idx = self.global_block_idx(piece_idx, block_idx);
            if let Some(block) = self.blocks.get_mut(global_idx)
                && matches!(block.state, BlockState::Requested { .. })
            {
                block.state = BlockState::Missing;
                affected_pieces.insert(block_id.piece);
            }
        }

        for piece_idx in affected_pieces {
            let Ok(blocks_cnt) = self.blocks_in_piece(piece_idx) else {
                continue;
            };
            let start_block_idx = piece_idx * self.blocks_in_full_piece;
            let all_blocks_missing = (0..blocks_cnt).all(|b| {
                matches!(
                    self.blocks.get(start_block_idx + b).map(|bl| &bl.state),
                    Some(BlockState::Missing),
                )
            });
            if all_blocks_missing
                && let Some(p) = self.pieces.get_mut(piece_idx)
                && matches!(p, PieceState::InProgress)
            {
                *p = PieceState::Missing;
            }
        }
    }

    pub(crate) fn mark_piece_done(&mut self, piece_idx: usize) -> Result<(), PieceManagerErr> {
        let blocks_cnt = self.blocks_in_piece(piece_idx)?;
        let start = piece_idx * self.blocks_in_full_piece;
        let all_received = (0..blocks_cnt).all(|b| {
            matches!(
                self.blocks.get(start + b),
                Some(Block {
                    state: BlockState::Received
                })
            )
        });
        if !all_received {
            return Err(PieceManagerErr::PieceIncomplete);
        }

        let piece = self
            .pieces
            .get_mut(piece_idx)
            .ok_or(PieceManagerErr::PieceIndexOutOfRange(piece_idx))?;
        *piece = PieceState::Done;
        self.own_bitfield.set(piece_idx, true);
        Ok(())
    }

    pub(crate) fn mark_block_requested(
        &mut self,
        block_id: BlockId,
        peer: &PeerId,
    ) -> Result<(), PieceManagerErr> {
        let (peer_state, block) = self.locate_block_mut(block_id, peer)?;
        if !matches!(block.state, BlockState::Missing) {
            return Err(PieceManagerErr::BlockNotMissing);
        }

        block.state = BlockState::Requested { at: Instant::now() };
        peer_state.in_flight.insert(block_id);

        if let Some(p) = self.pieces.get_mut(block_id.piece)
            && matches!(p, PieceState::Missing)
        {
            *p = PieceState::InProgress;
        }

        Ok(())
    }

    pub(crate) fn mark_block_received(
        &mut self,
        block_id: BlockId,
        peer: &PeerId,
    ) -> Result<(), PieceManagerErr> {
        let (peer_state, block) = self.locate_block_mut(block_id, peer)?;
        if !matches!(block.state, BlockState::Requested { .. }) {
            return Err(PieceManagerErr::BlockNotRequested);
        }

        if !peer_state.in_flight.contains(&block_id) {
            return Err(PieceManagerErr::BlockNotRequestedFromPeer);
        }

        block.state = BlockState::Received;
        peer_state.in_flight.remove(&block_id);

        Ok(())
    }

    fn locate_block_mut(
        &mut self,
        block_id: BlockId,
        peer: &PeerId,
    ) -> Result<(&mut PeerState, &mut Block), PieceManagerErr> {
        let block_idx = block_id.index;
        let piece_idx = block_id.piece;

        if piece_idx >= self.pieces.len() {
            return Err(PieceManagerErr::PieceIndexOutOfRange(piece_idx));
        }

        let blocks_in_piece = self.blocks_in_piece(piece_idx)?;
        if block_idx >= blocks_in_piece {
            return Err(PieceManagerErr::BlockOutOfRange {
                block_idx,
                piece_idx,
            });
        }

        let global = self.global_block_idx(piece_idx, block_idx);

        let peer_state = self
            .peers
            .get_mut(peer)
            .ok_or(PieceManagerErr::UnknownPeer)?;

        let block = self
            .blocks
            .get_mut(global)
            .ok_or(PieceManagerErr::BlockOutOfRange {
                block_idx,
                piece_idx,
            })?;

        Ok((peer_state, block))
    }

    fn global_block_idx(&self, piece_idx: usize, block_idx: usize) -> usize {
        piece_idx * self.blocks_in_full_piece + block_idx
    }
}

// TODO: FirstAvailable, RarestFirst, RandomFirst, Endgame
pub trait PieceStrategy {
    fn pick_piece(&self, pm: &PieceManager, peer: PeerId) -> Option<usize>;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn make_pm() -> PieceManager {
        let peer = Arc::new(Peer::Compact(Ipv4Addr::LOCALHOST, 8080));
        let piece_size = 1 << 19;
        let piece_cnt = 8;
        let hashes = vec![[0u8; 20]; piece_cnt];
        let total_size = (1 << 22) + 15;

        PieceManager::new(hashes, piece_size, total_size).unwrap()
    }

    fn make_peer() -> Arc<Peer> {
        Arc::new(Peer::Compact(Ipv4Addr::LOCALHOST, 8080))
    }

    #[test]
    fn last_piece_size() {
        let pm = make_pm();
        let last_piece = pm.piece_size(7).unwrap();
        let piece1 = pm.piece_size(1).unwrap();
        let piece2 = pm.piece_size(2).unwrap();

        assert_eq!(piece2, piece1);
        assert_eq!(piece1, 1 << 19);
        assert_eq!(last_piece, 15);
    }

    #[test]
    fn block_cnt() {}
}
