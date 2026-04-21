use crate::torrent::{metadata::parse_torrent, session::TorrentSession};

mod encoding;
mod torrent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mtorrent_file =
        parse_torrent(include_bytes!("./torrent/testdata/test_multi.torrent")).unwrap();
    let storrent_file =
        parse_torrent(include_bytes!("./torrent/testdata/test_single.torrent")).unwrap();

    //print!("{}", mtorrent_file);
    //println!("*******");
    //
    //print!("{}\n", storrent_file);

    //let real_torrent_file =
    //parse_torrent(include_bytes!("../testdata/test_dir_of.torrent")).unwrap();
    let real_torrent_file = parse_torrent(include_bytes!(
        "../../vortex-test/work/torrent/single.torrent"
    ))
    .unwrap();
    println!("{}", real_torrent_file);

    eprintln!("calling {}", real_torrent_file.announce);

    let mut ts = TorrentSession::new(
        &real_torrent_file,
        Some("kek.ru".to_string()),
        6881,
        Some(80),
    );

    ts.start_session().await?;
    let peers = ts.request_peers_body().await.unwrap();
    let hexe_peers = hex::encode(peers);
    eprintln!("hx: {hexe_peers}");

    // println!("{}", real_torrent_file);

    Ok(())
}
