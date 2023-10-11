// Copyright 2023 Remi Bernotavicius

use chrono::{offset::TimeZone as _, Local};
use clap::Parser;
use smb3_client::Result;
use std::net::TcpStream;

#[derive(Parser)]
struct Options {
    host: String,
    tree_path: String,
    #[clap(long, default_value_t = smb3_client::PORT)]
    port: u16,
    #[clap(long)]
    username: String,
    #[clap(long)]
    password: String,
}

fn main() -> Result<()> {
    let opts = Options::parse();

    let transport = TcpStream::connect((opts.host, opts.port))?;
    let mut client =
        smb3_client::Client::new(transport, &opts.username, &opts.password, &opts.tree_path)?;
    let root = client.open_root()?;
    let resp = client.query_directory(root)?;
    for entry in resp {
        let change_str = Local
            .from_local_datetime(&entry.change_time.to_date_time())
            .unwrap()
            .to_rfc2822();
        let file_name = entry.file_name;
        println!("{change_str:31} {file_name}");
    }

    Ok(())
}
