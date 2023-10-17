// Copyright Remi Bernotavicius

use assert_matches::assert_matches;
use serde::de::DeserializeOwned;
use smb3::{
    AccessMask, FileAccessInformation, FileAlignmentInformation, FileAlignmentRequirement,
    FileAllInformation, FileAttributes, FileBasicInformation, FileEaInformation, FileId,
    FileInternalInformation, FileMode, FileModeInformation, FileNameInformation,
    FilePositionInformation, FileStandardInformation, HasFileInformationClass, NtStatus, Time,
};
use smb3_client::{Client, Error, PORT};
use std::collections::BTreeSet;
use std::net::TcpStream;

macro_rules! test {
    ($test_name:ident) => {
        (Self::$test_name as fn(&mut Self), stringify!($test_name))
    };
}

struct Fixture<'machine> {
    machine: &'machine mut vm_runner::Machine,
    client: Client<TcpStream>,
}

impl<'machine> Fixture<'machine> {
    fn new(machine: &'machine mut vm_runner::Machine) -> Self {
        let port = machine
            .forwarded_ports()
            .iter()
            .find(|p| p.guest == PORT)
            .unwrap();
        let transport = TcpStream::connect(("127.0.0.1", port.host)).unwrap();
        let client = Client::new(transport, "root", "a", "files").unwrap();

        Self { machine, client }
    }

    fn run(&mut self) {
        let tests = [
            test!(query_directory_test),
            test!(query_info_test),
            test!(read_write_test),
            test!(delete_test),
        ];

        for (test, test_name) in tests {
            log::info!("running test {}:Fixture::{}", file!(), test_name);
            test(self);
            self.machine.run_command("rm -rf /files/*");
        }
    }

    //  _          _
    // | |__   ___| |_ __   ___ _ __ ___
    // | '_ \ / _ \ | '_ \ / _ \ '__/ __|
    // | | | |  __/ | |_) |  __/ |  \__ \
    // |_| |_|\___|_| .__/ \___|_|  |___/
    //              |_|

    fn get_file_size(&mut self, path: &str) -> u64 {
        let file_id = self.client.look_up(path).unwrap();
        let reply: FileStandardInformation = self.client.query_info(file_id).unwrap();
        self.client.close(file_id).unwrap();
        reply.end_of_file
    }

    fn query_info<Info: DeserializeOwned + HasFileInformationClass>(
        &mut self,
        file_id: FileId,
    ) -> Info {
        self.client.query_info::<Info>(file_id).unwrap()
    }

    //  _            _
    // | |_ ___  ___| |_ ___
    // | __/ _ \/ __| __/ __|
    // | ||  __/\__ \ |_\__ \
    //  \__\___||___/\__|___/
    //

    fn query_directory_test(&mut self) {
        self.machine.run_command("touch /files/a /files/b /files/c");
        let root = self.client.look_up("/").unwrap();
        let entries_vec = self.client.query_directory(root).unwrap();
        let entries: BTreeSet<_> = entries_vec.iter().map(|e| e.file_name.as_str()).collect();
        assert_eq!(entries, BTreeSet::from_iter([".", "..", "a", "b", "c"]));
        self.client.close(root).unwrap();
    }

    fn read_write_test(&mut self) {
        let file_id = self.client.create_file("/a_file").unwrap();

        let test_contents: Vec<u8> = (0..100_000).map(|v| (v % 255) as u8).collect();
        self.client
            .write_all(file_id.clone(), &test_contents[..])
            .unwrap();
        self.client.flush(file_id).unwrap();

        let file_id = self.client.look_up("/a_file").unwrap();
        let mut read_data = vec![];
        self.client
            .read_all(file_id.clone(), &mut read_data)
            .unwrap();
        assert_eq!(read_data, test_contents);

        assert_eq!(self.get_file_size("/a_file"), read_data.len() as u64);

        self.client.close(file_id).unwrap();
    }

    fn query_info_test(&mut self) {
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

        let file_id = self.client.create_file("/a_file").unwrap();
        let r: FileAllInformation = self.client.query_info(file_id).unwrap();

        // This are unpredictable
        expected.basic.creation_time = r.basic.creation_time.clone();
        expected.basic.last_access_time = r.basic.last_access_time.clone();
        expected.basic.last_write_time = r.basic.last_write_time.clone();
        expected.basic.change_time = r.basic.change_time.clone();

        assert_eq!(r, expected);

        assert_eq!(
            self.query_info::<FileBasicInformation>(file_id),
            expected.basic
        );
        assert_eq!(
            self.query_info::<FileStandardInformation>(file_id),
            expected.standard
        );
        assert_eq!(
            self.query_info::<FileInternalInformation>(file_id),
            expected.internal
        );
        assert_eq!(self.query_info::<FileEaInformation>(file_id), expected.ea);
        assert_eq!(
            self.query_info::<FileAccessInformation>(file_id),
            expected.access
        );
        assert_eq!(
            self.query_info::<FilePositionInformation>(file_id),
            expected.position
        );
        assert_eq!(
            self.query_info::<FileModeInformation>(file_id),
            expected.mode
        );
        assert_eq!(
            self.query_info::<FileAlignmentInformation>(file_id),
            expected.alignment
        );
        assert_eq!(
            self.query_info::<FileNameInformation>(file_id),
            expected.name
        );

        self.client.close(file_id).unwrap();
    }

    fn delete_test(&mut self) {
        let file_id = self.client.create_file("/a_file").unwrap();
        self.client.close(file_id).unwrap();
        self.client.delete("/a_file").unwrap();
        assert_matches!(
            self.client.look_up("/a_file").unwrap_err(),
            Error::NtStatus(NtStatus::ObjectNameNotFound)
        );
    }
}

#[test]
fn linux_server() {
    vm_test_fixture::fixture(&[PORT], |m| {
        let mut fix = Fixture::new(m);
        fix.run();
    });
}
