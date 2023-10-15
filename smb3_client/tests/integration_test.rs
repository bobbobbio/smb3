// Copyright Remi Bernotavicius

use smb3_client::Client;
use smb3_client::PORT;
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
        let tests = [test!(query_directory_test), test!(read_write_test)];

        for (test, test_name) in tests {
            log::info!("running test {}:Fixture::{}", file!(), test_name);
            test(self);
            self.machine.run_command("rm -rf /files/*");
        }
    }

    fn query_directory_test(&mut self) {
        self.machine.run_command("touch /files/a /files/b /files/c");
        let root = self.client.look_up("/").unwrap();
        let entries_vec = self.client.query_directory(root).unwrap();
        let entries: BTreeSet<_> = entries_vec.iter().map(|e| e.file_name.as_str()).collect();
        assert_eq!(entries, BTreeSet::from_iter([".", "..", "a", "b", "c"]));
    }

    fn read_write_test(&mut self) {
        let file_id = self.client.create_file("/a_file").unwrap();

        let test_contents: Vec<u8> = (0..100_000).map(|v| (v % 255) as u8).collect();
        self.client
            .write_all(file_id.clone(), &test_contents[..])
            .unwrap();

        let file_id = self.client.look_up("/a_file").unwrap();
        let mut read_data = vec![];
        self.client
            .read_all(file_id.clone(), &mut read_data)
            .unwrap();
        assert_eq!(read_data, test_contents);
    }
}

#[test]
fn linux_server() {
    vm_test_fixture::fixture(&[PORT], |m| {
        let mut fix = Fixture::new(m);
        fix.run();
    });
}
