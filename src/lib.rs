// Copyright 2018, Joren Van Onder (joren.vanonder@gmail.com)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

fn print_entries(entries: &HashMap<String, SocketAddr>) {
    const NAME_WIDTH: usize = 32;
    const ADDR_WIDTH: usize = 21; // max: 123.123.123.123:65535
    println!(
        "{:^width$}",
        "--- CONNECTED CLIENTS ---",
        width = NAME_WIDTH + ADDR_WIDTH
    );
    for (name, entry) in entries {
        println!(
            "{:<name_width$}{:>addr_width$}",
            name,
            entry,
            name_width = NAME_WIDTH,
            addr_width = ADDR_WIDTH
        );
    }
}

fn parse_ask_msg(msg: Vec<u8>) -> (Ipv4Addr, u16) {
    let dest_ip = Ipv4Addr::new(msg[0], msg[1], msg[2], msg[3]);
    let dest_port: u16 = ((msg[4] as u16) << 8) + msg[5] as u16;

    (dest_ip, dest_port)
}

fn send_request(
    socket: &UdpSocket,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    return_ip: Ipv4Addr,
    return_port: u16,
) {
    let mut msg: Vec<u8> = "SEND".as_bytes().to_vec();
    msg.extend_from_slice(&return_ip.octets());
    msg.push((return_port >> 8) as u8);
    msg.push((return_port & 0xff) as u8);

    println!(
        "{}:{} should send to {}:{}",
        dest_ip, dest_port, return_ip, return_port
    );

    socket
        .send_to(&msg, format!("{}:{}", dest_ip, dest_port))
        .unwrap();
}

fn set_up_socket() -> UdpSocket {
    const PORT: u32 = 63325;
    // Don't bind to 127.0.0.1, it will bind to the loopback interface
    // which makes it impossible to send_to.
    UdpSocket::bind(format!("0.0.0.0:{}", PORT)).unwrap()
}

fn addr_to_ip_port(addr: &SocketAddr) -> (Ipv4Addr, u16) {
    let ip = match addr.ip() {
        IpAddr::V4(ip) => ip,
        _ => panic!("Only v4 is supported\n"),
    };
    let port = addr.port();

    (ip, port)
}

fn send_list(socket: &UdpSocket, client: &SocketAddr, entries: &HashMap<String, SocketAddr>) {
    const USERNAME_BYTES: usize = 32;
    let mut msg: Vec<u8> = vec![];

    // each client: 4 bytes IP, 2 bytes port, 32 bytes name
    for (name, addr) in entries {
        // don't list the client doing the request
        if addr == client {
            continue;
        }

        let (ip, port) = addr_to_ip_port(&addr);
        msg.extend_from_slice(&ip.octets());
        msg.push((port >> 8) as u8);
        msg.push((port & 0xff) as u8);

        let mut username: Vec<u8> = name.as_bytes().to_vec();
        username.resize(USERNAME_BYTES, 0);
        msg.append(&mut username);
    }

    socket.send_to(&msg, client).unwrap();
}

pub fn run() {
    let mut entries: HashMap<String, SocketAddr> = HashMap::new();
    let socket = set_up_socket();

    loop {
        // The message has the following format:
        //
        // 0       8      16      24      32
        // |-------+-------+-------+-------|
        // |  TYPE |        CONTENT        |
        // |-------+-------+-------+-------|
        //
        // TYPE is an ASCII encoded string and can be:
        //
        // - REGISTER, or
        // - LIST, or
        // - ASK
        //
        // CONTENT depends on TYPE:
        //
        // - for REGISTER:
        //
        // 8          9         10         11         12         13         14 ....... 32
        // |----------+----------+----------+----------+----------+----------+----------+
        // | IPv4 MSB |  IPv4 B  |  IPv4 B  | IPv4 LSB | UDP PORT | UDP PORT | USERNAME |
        // |          |          |          |          |   MSB    |   LSB    |  UTF-8   |
        // |----------+----------+----------+----------+----------+----------+----------|
        //
        // - for LIST CONTENT is unused,
        // - for ASK the first 32 bytes contain USERNAME
        let mut buf = [0; 32];
        let (amt, src) = socket.recv_from(&mut buf).unwrap();

        let (src_ip, src_port) = addr_to_ip_port(&src);
        let msg_type = String::from_utf8(buf[..8].to_vec()).unwrap();
        let msg_type = String::from(msg_type.trim_matches('\0'));

        println!("Received {} message from {} ({} bytes)", msg_type, src, amt);

        if msg_type.starts_with("LIST") {
            send_list(&socket, &src, &entries);
        } else if msg_type.starts_with("ASK") {
            let (dest_ip, port) = parse_ask_msg(buf[8..].to_vec());
            send_request(&socket, dest_ip, port, src_ip, src_port);
        } else if msg_type.starts_with("REGISTER") {
            let username = String::from_utf8(buf[8..].to_vec()).unwrap();
            let username = username.trim_matches('\0').to_string();

            if entries.get(&username).is_none() {
                entries.insert(username, src);
            } else {
                println!("{} is already taken, ignoring...", username);
            }

            print_entries(&entries);
            // reply with public IP
            socket.send_to(&src_ip.octets().to_vec(), &src).unwrap();
        } else {
            println!("invalid msg_type");
        }
    }
}
