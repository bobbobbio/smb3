// Copyright 2023 Remi Bernotavicius

use chrono::{offset::TimeZone as _, Local};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use smb3::FileAllInformation;
use smb3_client::Result;
use std::net::TcpStream;
use std::path::PathBuf;

#[derive(Subcommand)]
enum Command {
    ReadDir { path: PathBuf },
    Upload { local: PathBuf, remote: PathBuf },
    Download { remote: PathBuf, local: PathBuf },
    QueryInfo { remote: PathBuf },
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

    fn upload(&mut self, local: PathBuf, remote: PathBuf) -> Result<()> {
        let file_id = self.client.create_file(remote)?;
        let file = std::fs::File::open(local)?;
        let progress = ProgressBar::new(file.metadata()?.len()).with_style(
            ProgressStyle::with_template("{wide_bar} {percent}% {binary_bytes_per_sec}").unwrap(),
        );
        self.client.write_all(file_id, progress.wrap_read(file))?;
        Ok(())
    }

    fn download(&mut self, remote: PathBuf, local: PathBuf) -> Result<()> {
        let local_file = if local.to_string_lossy().ends_with('/') {
            local.join(remote.file_name().unwrap())
        } else {
            local
        };

        let file_id = self.client.look_up(&remote)?;

        let size = 5037662208;
        let progress = ProgressBar::new(size).with_style(
            ProgressStyle::with_template("{wide_bar} {percent}% {binary_bytes_per_sec}").unwrap(),
        );
        let file = std::fs::File::create(local_file)?;
        self.client.read_all(file_id, progress.wrap_write(file))?;
        Ok(())
    }

    fn query_info(&mut self, remote: PathBuf) -> Result<()> {
        let file_id = self.client.look_up(&remote)?;
        let info: FileAllInformation = self.client.query_info(file_id)?;
        println!("{info:#?}");
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
        Command::Download { remote, local } => cli.download(remote, local)?,
        Command::QueryInfo { remote } => cli.query_info(remote)?,
    }

    Ok(())
}
