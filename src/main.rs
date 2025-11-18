use crate::torrent::metadata::{Torrent, parse_torrent};

mod encoding;
mod torrent;

fn main() {
    let mtorrent_file =
        parse_torrent(include_bytes!("./torrent/testdata/test_multi.torrent")).unwrap();
    let storrent_file =
        parse_torrent(include_bytes!("./torrent/testdata/test_single.torrent")).unwrap();

    print!("{}", mtorrent_file);
    println!("*******");

    print!("{}", storrent_file);
}
