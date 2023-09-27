// Copyright 2023 Remi Bernotavicius

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
    println!("{resp:#?}");

    Ok(())
}
