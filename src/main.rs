use std::fs::write;
use std::net::{IpAddr, TcpStream};
use std::path::Path;
use std::thread::spawn;

use clap::Values;

/// a port sniffer that checks if any port on a given address is open
/// writes the open ports to FILE
///
/// ATTENTION: creates 36_535 threads!
/// ATTENTION:
fn main() {
    let args = parse_args();

    let address = args.address;
    let ports = args.ports;
    let total = ports.len();
    let output = args.output;

    let mut handles = Vec::new();
    let mut open_ports = String::new();
    let mut counter: u16 = 0;

    println!("Start port sniffing on {}", &address);
    println!("Total ports: {}\n", total);

    for port in ports {
        let handle = spawn(move || check_port(address, port));
        handles.push((port, handle));
    }

    for (port, handle) in handles {
        let open = handle.join().expect("Something went wrong!");

        open_ports.push_str(&format!("{};{}\n", port, open));

        if open {
            println!("Port {} is open", port);
            counter += 1;
        }
    }

    write(output, open_ports).expect("Could not write to file!");

    println!("\nFinished port sniffing");
    println!("Found {} open port(s)", counter);
}

struct Args<P: AsRef<Path>> {
    ports: Vec<u16>,
    address: IpAddr,
    output: P,
}

fn parse_args() -> Args<String> {
    use clap::{App, Arg};

    let matches = App::new("Port Sniffer")
        .about("A lightning-fast port sniffer written in Rust that can scan all 36535 ports in a matter of seconds.\n\n\
        The final result is saved as a csv in the format: <port>;<true|false>\\n\n\n\
        ATTENTION: The sniffer will create an enormous amount of threads!\n\
        ATTENTION: It's possible that you will experience internet lags!\n\
        ATTENTION: It's possible that you lose internet connection. \
        This should usually be a problem of you pc and not your router. Just disconnect and reconnect to your router.")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .arg(Arg::with_name("address")
            .help("The address of the server\nCan be either an IP or a domain")
            .takes_value(true)
            .required(true)
            .validator(|address| {
                if parse_address(&address).is_none() {
                    Err("Address needs to be a valid IP or domain".to_string())
                } else { Ok(()) }
            })
        )
        .arg(Arg::with_name("ports")
            .help("Let's you specify the ports to sniff\n\
            You can use patterns like: <port> <start>..<end> <start>..=<end>\n")
            .short("p")
            .long("ports")
            .takes_value(true)
            .multiple(true)
            .default_value("0..=36535")
            .validator(|port| {
                if parse_port(&port).is_none() {
                    Err("You can use patterns like: <port> <start>..<end> <start>..=<end>".to_string())
                } else { Ok(()) }
            })
        )
        .arg(Arg::with_name("output")
            .help("The output csv to save the result\n[default: <address>.csv]")
            .short("o")
            .long("output")
            .takes_value(true)
        )
        .get_matches();

    let ports = matches.values_of("ports").unwrap();
    let ports = parse_ports(ports).unwrap();

    let address_str = matches.value_of("address").unwrap();
    let address = parse_address(address_str).unwrap();

    let output = matches.value_of("output").unwrap_or(&format!("{}.csv", address_str)).to_string();

    Args {
        ports,
        address,
        output,
    }
}

fn parse_ports(ports: Values) -> Option<Vec<u16>> {
    let mut parsed = Vec::new();

    for port in ports {
        match parse_port(port) {
            Some(ports) => parsed.extend(ports),
            None => return None
        }
    }

    Some(parsed)
}

fn parse_port(port: &str) -> Option<Vec<u16>> {
    use regex::Regex;

    let ports_regex = Regex::new(r"^((?P<start>\d+)\.\.(?P<inclusive>=)?(?P<end>\d+)|(?P<single>\d+))$").unwrap();

    match ports_regex.captures(port) {
        Some(captures) => {
            if captures.name("single").is_some() {
                let single = captures.name("single").unwrap().as_str();
                let single: u16 = single.parse().unwrap();
                Some(vec![single])
            } else {
                let start = captures.name("start").unwrap().as_str();
                let start: u16 = start.parse().unwrap();

                let end = captures.name("end").unwrap().as_str();
                let end: u16 = end.parse().unwrap();

                let inclusive = captures.name("inclusive").is_some();

                if inclusive {
                    Some((start..=end).collect::<Vec<u16>>())
                } else {
                    Some((start..end).collect::<Vec<u16>>())
                }
            }
        }
        None => None
    }
}

fn parse_address(address: &str) -> Option<IpAddr> {
    use dns_lookup::lookup_host;

    match address.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
            match lookup_host(address) {
                Ok(ips) if ips.len() == 1 => Some(ips[0]),
                _ => None
            }
        }
    }
}

fn check_port(address: IpAddr, port: u16) -> bool {
    match TcpStream::connect((address, port)) {
        Ok(_) => true,
        Err(_) => false
    }
}
