// Copyright Remi Bernotavicius

use smb3_client::Client;
use smb3_client::PORT;
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
        let tests = [test!(query_directory_test)];

        for (test, test_name) in tests {
            log::info!("running test {}:Fixture::{}", file!(), test_name);
            test(self);
            self.machine.run_command("rm -rf /files/*");
        }
    }

    fn query_directory_test(&mut self) {
        let root = self.client.open_root().unwrap();
        self.client.query_directory(root).unwrap();
    }
}

#[test]
fn linux_server() {
    vm_test_fixture::fixture(&[PORT], |m| {
        let mut fix = Fixture::new(m);
        fix.run();
    });
}