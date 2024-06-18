// Copyright Remi Bernotavicius

use assert_matches::assert_matches;
use serde::de::DeserializeOwned;
use smb3::{
    AccessMask, FileAccessInformation, FileAlignmentInformation, FileAlignmentRequirement,
    FileAllInformation, FileAttributes, FileBasicInformation, FileEaInformation,
    FileEndOfFileInformation, FileId, FileInternalInformation, FileMode, FileModeInformation,
    FileNameInformation, FilePositionInformation, FileStandardInformation, HasFileInformationClass,
    NtStatus, Time,
};
use smb3_client::{Client, Error, PORT};
use std::collections::BTreeSet;
use tokio::net::TcpStream;

macro_rules! test {
    ($self:expr, $test_name:ident) => {
        log::info!(
            "running test {}:Fixture::{}",
            file!(),
            stringify!($test_name)
        );
        $self.$test_name().await;
        $self.machine.run_command("rm -rf /files/*");
    };
}

struct Fixture<'machine> {
    machine: &'machine mut vm_runner::Machine,
    client: Client<TcpStream>,
}

impl<'machine> Fixture<'machine> {
    async fn new(machine: &'machine mut vm_runner::Machine) -> Self {
        let port = machine
            .forwarded_ports()
            .iter()
            .find(|p| p.guest == PORT)
            .unwrap();
        let transport = TcpStream::connect(("127.0.0.1", port.host)).await.unwrap();
        let client = Client::new(transport, "root", "a", "files").await.unwrap();

        Self { machine, client }
    }

    async fn run(&mut self) {
        test!(self, delete_test);
        test!(self, query_directory_test_large);
        test!(self, query_directory_test_small);
        test!(self, query_info_test);
        test!(self, read_write_test);
        test!(self, rename_test);
        test!(self, resize_test);
    }

    //  _          _
    // | |__   ___| |_ __   ___ _ __ ___
    // | '_ \ / _ \ | '_ \ / _ \ '__/ __|
    // | | | |  __/ | |_) |  __/ |  \__ \
    // |_| |_|\___|_| .__/ \___|_|  |___/
    //              |_|

    async fn get_file_size(&mut self, path: &str) -> i64 {
        let file_id = self.client.look_up(path).await.unwrap();
        let reply: FileStandardInformation = self.client.query_info(file_id).await.unwrap();
        self.client.close(file_id).await.unwrap();
        reply.end_of_file
    }

    async fn query_info<Info: DeserializeOwned + HasFileInformationClass>(
        &mut self,
        file_id: FileId,
    ) -> Info {
        self.client.query_info::<Info>(file_id).await.unwrap()
    }

    //  _            _
    // | |_ ___  ___| |_ ___
    // | __/ _ \/ __| __/ __|
    // | ||  __/\__ \ |_\__ \
    //  \__\___||___/\__|___/
    //

    async fn query_directory_test_with_dir_size(&mut self, size: usize) {
        // Create entries with pretty large names, this helps us ensure some pagination
        let entries_to_create: Vec<_> = (0..size)
            .map(|n| {
                format!(
                    "{}_{n}",
                    std::iter::repeat('a').take(120).collect::<String>()
                )
            })
            .collect();
        for f in &entries_to_create {
            let file_id = self.client.create_file(format!("/{f}")).await.unwrap();
            self.client.close(file_id).await.unwrap();
        }

        let root = self.client.look_up("/").await.unwrap();
        let entries_vec = self.client.query_directory(root).await.unwrap();
        let entries: BTreeSet<_> = entries_vec.into_iter().map(|e| e.file_name).collect();
        let expected_entires = BTreeSet::from_iter(
            [".".into(), "..".into()]
                .into_iter()
                .chain(entries_to_create.into_iter()),
        );
        assert_eq!(entries.len(), expected_entires.len());
        assert_eq!(entries, expected_entires);
        self.client.close(root).await.unwrap();
    }

    async fn query_directory_test_small(&mut self) {
        self.query_directory_test_with_dir_size(5).await;
    }

    async fn query_directory_test_large(&mut self) {
        self.query_directory_test_with_dir_size(60).await;
    }

    async fn read_write_test(&mut self) {
        let file_id = self.client.create_file("/a_file").await.unwrap();

        let test_contents: Vec<u8> = (0..100_000).map(|v| (v % 255) as u8).collect();
        self.client
            .write_all(file_id.clone(), &test_contents[..])
            .await
            .unwrap();
        self.client.flush(file_id).await.unwrap();

        let file_id = self.client.look_up("/a_file").await.unwrap();
        let mut read_data = vec![];
        self.client
            .read_all(file_id.clone(), &mut read_data)
            .await
            .unwrap();
        assert_eq!(read_data, test_contents);

        assert_eq!(self.get_file_size("/a_file").await, read_data.len() as i64);

        self.client.close(file_id).await.unwrap();
    }

    async fn query_info_test(&mut self) {
        let mut expected = FileAllInformation {
            basic: FileBasicInformation {
                creation_time: Time { intervals: 0 },
                last_access_time: Time { intervals: 0 },
                last_write_time: Time { intervals: 0 },
                change_time: Time { intervals: 0 },
                file_attributes: FileAttributes::ARCHIVE,
            },
            standard: FileStandardInformation {
                allocation_size: 0,
                end_of_file: 0,
                number_of_links: 1,
                delete_pending: false,
                directory: false,
            },
            internal: FileInternalInformation {
                index_number: 65101,
            },
            ea: FileEaInformation { ea_size: 0 },
            access: FileAccessInformation {
                access_flags: AccessMask::FILE_WRITE_DATA
                    | AccessMask::FILE_APPEND_DATA
                    | AccessMask::FILE_WRITE_EA
                    | AccessMask::FILE_READ_ATTRIBUTES
                    | AccessMask::FILE_WRITE_ATTRIBUTES
                    | AccessMask::READ_CONTROL
                    | AccessMask::SYNCHRONIZE,
            },
            position: FilePositionInformation {
                current_byte_offset: 0,
            },
            mode: FileModeInformation {
                mode: FileMode::SYNCHRONOUS_IO_NONALERT,
            },
            alignment: FileAlignmentInformation {
                alignment_requirement: FileAlignmentRequirement::FileByteAlignment,
            },
            name: FileNameInformation {
                name: "\\a_file".into(),
            },
        };

        let file_id = self.client.create_file("/a_file").await.unwrap();
        let r: FileAllInformation = self.client.query_info(file_id).await.unwrap();

        // This are unpredictable
        expected.basic.creation_time = r.basic.creation_time.clone();
        expected.basic.last_access_time = r.basic.last_access_time.clone();
        expected.basic.last_write_time = r.basic.last_write_time.clone();
        expected.basic.change_time = r.basic.change_time.clone();
        expected.internal = r.internal.clone();

        assert_eq!(r, expected);

        assert_eq!(
            self.query_info::<FileBasicInformation>(file_id).await,
            expected.basic
        );
        assert_eq!(
            self.query_info::<FileStandardInformation>(file_id).await,
            expected.standard
        );
        assert_eq!(
            self.query_info::<FileInternalInformation>(file_id).await,
            expected.internal
        );
        assert_eq!(
            self.query_info::<FileEaInformation>(file_id).await,
            expected.ea
        );
        assert_eq!(
            self.query_info::<FileAccessInformation>(file_id).await,
            expected.access
        );
        assert_eq!(
            self.query_info::<FilePositionInformation>(file_id).await,
            expected.position
        );
        assert_eq!(
            self.query_info::<FileModeInformation>(file_id).await,
            expected.mode
        );
        assert_eq!(
            self.query_info::<FileAlignmentInformation>(file_id).await,
            expected.alignment
        );
        assert_eq!(
            self.query_info::<FileNameInformation>(file_id).await,
            expected.name
        );

        self.client.close(file_id).await.unwrap();
    }

    async fn delete_test(&mut self) {
        let file_id = self.client.create_file("/a_file").await.unwrap();
        self.client.close(file_id).await.unwrap();
        self.client.delete("/a_file").await.unwrap();
        assert_matches!(
            self.client.look_up("/a_file").await.unwrap_err(),
            Error::NtStatus(NtStatus::ObjectNameNotFound)
        );
    }

    async fn rename_test(&mut self) {
        let file_id = self.client.create_file("/a_file").await.unwrap();
        self.client.rename(file_id, "/b_file").await.unwrap();
        self.client.close(file_id).await.unwrap();

        assert_matches!(
            self.client.look_up("/a_file").await.unwrap_err(),
            Error::NtStatus(NtStatus::ObjectNameNotFound)
        );
        let file_id = self.client.look_up("/b_file").await.unwrap();
        self.client.close(file_id).await.unwrap();
    }

    async fn resize_test(&mut self) {
        let file_id = self.client.create_file("/a_file").await.unwrap();
        self.client.resize(file_id, 10000).await.unwrap();
        let info: FileEndOfFileInformation = self.client.query_info(file_id).await.unwrap();
        assert_eq!(info.end_of_file, 10000);
        self.client.close(file_id).await.unwrap();
    }
}

#[tokio::main]
async fn run_fixture(m: &mut vm_runner::Machine) {
    let mut fix = Fixture::new(m).await;
    fix.run().await;
}

#[test]
fn linux_server() {
    vm_test_fixture::fixture(&[PORT], |m| run_fixture(m));
}
