use std::collections::BTreeMap;

use url::Url;

use crate::encoding::bencode::{Bencoded, DecodeErr, decode_single};

#[derive(Debug)]
enum TorrentFileErr {
    TorrentFileNotDict,
    DecodeErr(DecodeErr),
    NoAnnounce,
    AnnounceValIsNotByteStr,
    InfoNotADict,
    NoInfo,
    AnnounceValContainsNonUTF8,
    AnnounceLinkInvalidUrl(url::ParseError),
    InfoParseErr(InfoParseErr),
}

#[derive(Debug)]
enum InfoParseErr {
    ContainsLengthAndFiles,
    ContainsNeitherLengthNorFiles,
    NotContainName,
    NotContainPieceLength,
    PieceLengthNotUsize,
    NotContainPieces,
    LenNotInt,
    LenNotFitUsize,
    NameNotByteStr,
    NameNonUTF8,
    PieceLenNotInt,
    PicesNotByteStr,
    PiecesLenNotMultipleOf20,
    FilesNotList,
    FilesListEntryNotDict,
    FilesParseErr(InfoFilesParseErr),
}

#[derive(Debug)]
enum InfoFilesParseErr {
    NotList,
    EntryNotDict,
    EntryNoLength,
    EntryLengthNotInt,
    EntryLengthNotFitUsize,
    EntryNoPath,
    EntryPathNotList,
    FilePathNonUTF8,
    FilePathNotByteStr,
}

/// Metainfo file (.torrent file)
#[derive(Debug, Clone)]
pub struct Torrent {
    /// Announce url
    announce: url::Url,
    /// Info dictionary
    info: Info,
}

#[derive(Debug, Clone)]
struct Info {
    /// Number of bytes in each piece. Piece length is almost always a power
    /// of 2, most commonly 2^18 = 256K (BitTorrent prior to version 3.2 uses 2^20 = 1 M as default).
    piece_len: usize,
    /// Concatenated SHA-1 hashed of each peace.
    /// Fixed-size pieces which are all the same length except for
    /// possibly the last one which may be truncated.
    /// SHA-1 is 160 bit. 40 hex digits.
    pieces: Vec<[u8; 20]>,
    info_mode: InfoMode,
}

#[derive(Debug, Clone)]
enum InfoMode {
    SingleFile(SingleFileInfo),
    MultipleFiles(MultipleFilesInfo),
}

#[derive(Debug, Clone)]
struct SingleFileInfo {
    /// Suggested name to save file/dir as. UTF-8 encoded.
    name: String,
    /// Size of the file in bytes.
    length: usize,
}

#[derive(Debug, Clone)]
struct MultipleFilesInfo {
    // List of dicts with lengths and paths
    files: Vec<FilesEntry>,
    // Dir name
    name: String,
}

#[derive(Debug, Clone)]
struct FilesEntry {
    /// Size of file in bytes
    length: usize,
    /// Dirname or filename if it's last entry
    path: Vec<String>,
}

pub fn parse_torrent(torrent_file: &[u8]) -> Result<Torrent, TorrentFileErr> {
    let torrent_dict = decode_single(torrent_file)
        .map_err(TorrentFileErr::DecodeErr)?
        .extract_dict()
        .map_err(|_| TorrentFileErr::TorrentFileNotDict)?;

    let announce = Url::parse(
        std::str::from_utf8(
            &torrent_dict
                .get(b"announce".as_slice())
                .ok_or(TorrentFileErr::NoAnnounce)?
                .extract_bytestr()
                .map_err(|_| TorrentFileErr::AnnounceValIsNotByteStr)?,
        )
        .map_err(|_| TorrentFileErr::AnnounceValContainsNonUTF8)?,
    )
    .map_err(TorrentFileErr::AnnounceLinkInvalidUrl)?;

    let info = parse_info_dict(
        &torrent_dict
            .get(b"info".as_slice())
            .ok_or(TorrentFileErr::NoInfo)?
            .extract_dict()
            .map_err(|_| TorrentFileErr::InfoNotADict)?,
    )
    .map_err(TorrentFileErr::InfoParseErr)?;

    Ok(Torrent { announce, info })
}

fn parse_info_dict(info_dict: &BTreeMap<Vec<u8>, Bencoded>) -> Result<Info, InfoParseErr> {
    let name = std::str::from_utf8(
        &info_dict
            .get(b"name".as_slice())
            .ok_or(InfoParseErr::NotContainName)?
            .extract_bytestr()
            .map_err(|_| InfoParseErr::NameNotByteStr)?,
    )
    .map_err(|_| InfoParseErr::NameNonUTF8)?
    .to_string();

    let info_mode = match (
        info_dict.get(b"length".as_slice()),
        info_dict.get(b"files".as_slice()),
    ) {
        (None, None) => Err(InfoParseErr::ContainsNeitherLengthNorFiles),
        (Some(_), Some(_)) => Err(InfoParseErr::ContainsLengthAndFiles),
        (None, Some(files_dict)) => Ok(InfoMode::MultipleFiles(MultipleFilesInfo {
            files: parse_multifile_info(
                files_dict
                    .extract_list()
                    .map_err(|_| InfoParseErr::FilesNotList)?,
            )
            .map_err(InfoParseErr::FilesParseErr)?,
            name,
        })),
        (Some(length), None) => Ok(InfoMode::SingleFile(SingleFileInfo {
            length: usize::try_from(length.extract_int().map_err(|_| InfoParseErr::LenNotInt)?)
                .map_err(|_| InfoParseErr::LenNotFitUsize)?,
            name,
        })),
    }?;

    let piece_len = usize::try_from(
        info_dict
            .get(b"piece length".as_slice())
            .ok_or(InfoParseErr::NotContainPieceLength)?
            .extract_int()
            .map_err(|_| InfoParseErr::PieceLenNotInt)?,
    )
    .map_err(|_| InfoParseErr::PieceLengthNotUsize)?;

    let pieces_bytestr = info_dict
        .get(b"pieces".as_slice())
        .ok_or(InfoParseErr::NotContainPieces)?
        .extract_bytestr()
        .map_err(|_| InfoParseErr::PicesNotByteStr)?;

    let pieces = pieces_bytestr
        .chunks_exact(20)
        .map(<[u8; 20]>::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InfoParseErr::PiecesLenNotMultipleOf20)?;

    Ok(Info {
        piece_len,
        pieces,
        info_mode,
    })
}

fn parse_multifile_info(files_list: Vec<Bencoded>) -> Result<Vec<FilesEntry>, InfoFilesParseErr> {
    files_list
        .iter()
        .map(|file_entry_dict| {
            file_entry_dict
                .extract_dict()
                .map_err(|_| InfoFilesParseErr::EntryNotDict)
                .and_then(|file_entry| {
                    let length = usize::try_from(
                        file_entry
                            .get(b"length".as_slice())
                            .ok_or(InfoFilesParseErr::EntryNoLength)?
                            .extract_int()
                            .map_err(|_| InfoFilesParseErr::EntryLengthNotInt)?,
                    )
                    .map_err(|_| InfoFilesParseErr::EntryLengthNotFitUsize)?;

                    let path = file_entry
                        .get(b"path".as_slice())
                        .ok_or(InfoFilesParseErr::EntryNoPath)?
                        .extract_list()
                        .map_err(|_| InfoFilesParseErr::EntryPathNotList)?
                        .iter()
                        .map(|path_part| {
                            std::str::from_utf8(
                                &path_part
                                    .extract_bytestr()
                                    .map_err(|_| InfoFilesParseErr::FilePathNotByteStr)?,
                            )
                            .map_err(|_| InfoFilesParseErr::FilePathNonUTF8)
                            .map(|s| s.to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                    Ok(FilesEntry { length, path })
                })
        })
        .collect()
}
