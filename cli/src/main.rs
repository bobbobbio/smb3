// Copyright 2023 Remi Bernotavicius

use chrono::{offset::TimeZone as _, Local};
use clap::{Parser, Subcommand};
use smb3_client::Result;
use std::net::TcpStream;
use std::path::PathBuf;

#[derive(Subcommand)]
enum Command {
    ReadDir { path: PathBuf },
    Upload { local: PathBuf, remote: PathBuf },
}

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
    #[command(subcommand)]
    command: Command,
}

struct Cli {
    client: smb3_client::Client<TcpStream>,
}

impl Cli {
    fn read_dir(&mut self, path: PathBuf) -> Result<()> {
        let root = self.client.look_up(path)?;
        let resp = self.client.query_directory(root)?;
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

    fn upload(&mut self, _local: PathBuf, remote: PathBuf) -> Result<()> {
        self.client.create_file(remote)?;
        // TODO
        Ok(())
    }
}

fn main() -> Result<()> {
    let opts = Options::parse();

    let transport = TcpStream::connect((opts.host, opts.port))?;
    let client =
        smb3_client::Client::new(transport, &opts.username, &opts.password, &opts.tree_path)?;

    let mut cli = Cli { client };
    match opts.command {
        Command::ReadDir { path } => cli.read_dir(path)?,
        Command::Upload { local, remote } => cli.upload(local, remote)?,
    }

    Ok(())
}
