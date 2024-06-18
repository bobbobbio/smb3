// Copyright 2023 Remi Bernotavicius

use chrono::{offset::TimeZone as _, Local};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use smb3::FileAllInformation;
use smb3_client::Result;
use std::path::PathBuf;
use tokio::net::TcpStream;

#[derive(Subcommand)]
enum Command {
    ReadDir {
        path: PathBuf,
    },
    Upload {
        local: PathBuf,
        remote: PathBuf,
    },
    Download {
        remote: PathBuf,
        local: PathBuf,
    },
    QueryInfo {
        remote: PathBuf,
    },
    Delete {
        remote: PathBuf,
    },
    Rename {
        remote_src: PathBuf,
        remote_target: PathBuf,
    },
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
    async fn read_dir(&mut self, path: PathBuf) -> Result<()> {
        let root = self.client.look_up(path).await?;
        let resp = self.client.query_directory(root).await?;
        for entry in resp {
            let change_str = Local
                .from_local_datetime(&entry.change_time.to_date_time())
                .unwrap()
                .to_rfc2822();
            let file_name = entry.file_name;
            println!("{change_str:31} {file_name}");
        }
        self.client.close(root).await?;
        Ok(())
    }

    async fn upload(&mut self, local: PathBuf, remote: PathBuf) -> Result<()> {
        let file_id = self.client.create_file(remote).await?;
        let file = tokio::fs::File::open(local).await?;
        let progress = ProgressBar::new(file.metadata().await?.len()).with_style(
            ProgressStyle::with_template("{wide_bar} {percent}% {binary_bytes_per_sec}").unwrap(),
        );
        self.client
            .write_all(file_id, progress.wrap_async_read(file))
            .await?;
        self.client.flush(file_id).await?;
        self.client.close(file_id).await?;
        Ok(())
    }

    async fn download(&mut self, remote: PathBuf, local: PathBuf) -> Result<()> {
        let local_file = if local.to_string_lossy().ends_with('/') {
            local.join(remote.file_name().unwrap())
        } else {
            local
        };

        let file_id = self.client.look_up(&remote).await?;

        let size = 5037662208;
        let progress = ProgressBar::new(size).with_style(
            ProgressStyle::with_template("{wide_bar} {percent}% {binary_bytes_per_sec}").unwrap(),
        );
        let file = tokio::fs::File::create(local_file).await?;
        self.client
            .read_all(file_id, progress.wrap_async_write(file))
            .await?;
        self.client.close(file_id).await?;

        Ok(())
    }

    async fn query_info(&mut self, remote: PathBuf) -> Result<()> {
        let file_id = self.client.look_up(&remote).await?;
        let info: FileAllInformation = self.client.query_info(file_id).await?;
        println!("{info:#?}");
        self.client.close(file_id).await?;
        Ok(())
    }

    async fn delete(&mut self, remote: PathBuf) -> Result<()> {
        self.client.delete(remote).await?;
        Ok(())
    }

    async fn rename(&mut self, remote_str: PathBuf, remote_target: PathBuf) -> Result<()> {
        let file_id = self.client.look_up(remote_str).await?;
        self.client.rename(file_id, remote_target).await?;
        self.client.close(file_id).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Options::parse();

    let transport = TcpStream::connect((opts.host, opts.port)).await?;
    let client =
        smb3_client::Client::new(transport, &opts.username, &opts.password, &opts.tree_path)
            .await?;

    let mut cli = Cli { client };
    match opts.command {
        Command::ReadDir { path } => cli.read_dir(path).await?,
        Command::Upload { local, remote } => cli.upload(local, remote).await?,
        Command::Download { remote, local } => cli.download(remote, local).await?,
        Command::QueryInfo { remote } => cli.query_info(remote).await?,
        Command::Delete { remote } => cli.delete(remote).await?,
        Command::Rename {
            remote_src,
            remote_target,
        } => cli.rename(remote_src, remote_target).await?,
    }

    Ok(())
}
