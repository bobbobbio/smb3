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
    let mut client = smb3_client::Client::new(transport, &opts.username, &opts.password)?;

    let (tree_id, response) = client.tree_connect(&opts.tree_path)?;
    println!("response = {response:#?}");
    println!("tree_id = {tree_id:?}");

    Ok(())
}
