use std::fs::write;
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::thread::spawn;

use clap;

const PORTS: u16 = 36_535;
const FILE: &str = "open_ports.csv";

/// a port sniffer that checks if any port on a given address is open
/// writes the open ports to FILE
///
/// ATTENTION: creates 36_535 threads!
fn main() {
    let matches = clap::App::new("Port Sniffer")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .arg(clap::Arg::with_name("address")
            .takes_value(true)
            .required(true)
        )
        .get_matches();

    let address: IpAddr = matches
        .value_of("address")
        .unwrap()
        .parse()
        .expect("Address needs to be a valid IP");

    let mut handles = Vec::new();
    let mut open_ports = String::new();
    let mut counter: u16 = 0;

    println!("Start port sniffing on {}", &address);
    println!("Ports: {} - {}\n", 0, PORTS);

    for port in 0..=PORTS {
        let handle = spawn(move || check_port(address, port));
        handles.push((port, handle));
    }

    for (port, handle) in handles {
        let open = handle.join().expect("Something went wrong!");

        if open {
            println!("Port {} is open", port);

            open_ports.push_str(&port.to_string());
            open_ports.push('\n');

            counter += 1;
        }
    }

    write(FILE, open_ports).expect("Could not write to file!");

    println!("\nFinished port sniffing");
    println!("Found {} open ports", counter);
}

fn check_port(address: IpAddr, port: u16) -> bool {
    match TcpStream::connect((address, port)) {
        Ok(_) => true,
        Err(_) => false
    }
}
