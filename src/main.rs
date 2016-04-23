extern crate pnet;

use std::time::{self,Instant,Duration};

use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ipv4::Ipv4Packet;

//use pnet::pnet_macros_support::types::*;

use std::net::{Ipv4Addr, Ipv6Addr};

extern {
        pub fn ip_compute_csum(buff: *const u8, len: u32) -> u16;
        pub fn csum_partial(buff: *const u8, len: u32, wsum: u32) -> u32;
        pub fn csum_partial_folded(buff: *const u8, len: u32, wsum: u32) -> u16;
}

/// Calculate the checksum for a packet built on IPv4
pub fn ipv4_checksum(packet: &TcpPacket, ipv4_source: Ipv4Addr,
                     ipv4_destination: Ipv4Addr,
                     next_level_protocol: IpNextHeaderProtocol) -> u16 {
    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    let mut sum = 0u32;
    let octets = ipv4_source.octets();
    sum += (octets[0] as u32) << 8 | (octets[1] as u32);
    sum += (octets[2] as u32) << 8 | (octets[3] as u32);
    let octets = ipv4_destination.octets();
    sum += (octets[0] as u32) << 8 | (octets[1] as u32);
    sum += (octets[2] as u32) << 8 | (octets[3] as u32);
    sum += next_level_protocol as u32;
    sum += packet.packet().len() as u32;
    let mut i = 0;
    let len = packet.packet().len();
    while i < len && i + 1 < len {
        sum +=
            (packet.packet()[i] as u32) << 8 |
                (packet.packet()[i + 1] as u32);
        i += 2;
    }
    if len & 1 != 0 { sum += (packet.packet()[len - 1] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum >> 16) + (sum & 65535); }
    !sum as u16
}

/// Calculate the checksum for a packet built on IPv4
pub fn ipv4_checksum_v2(packet: &TcpPacket, ipv4_source: Ipv4Addr,
                     ipv4_destination: Ipv4Addr,
                     next_level_protocol: IpNextHeaderProtocol) -> u16 {
    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    let mut sum = 0u32;
    let octets = ipv4_source.octets();
    sum += ((octets[0] as u16) << 8 | (octets[1] as u16)) as u32;
    sum += ((octets[2] as u16) << 8 | (octets[3] as u16)) as u32;

    let octets = ipv4_destination.octets();
    sum += ((octets[0] as u16) << 8 | (octets[1] as u16)) as u32;
    sum += ((octets[2] as u16) << 8 | (octets[3] as u16)) as u32;

    sum += next_level_protocol as u32;
    let bytes = packet.packet();
    let len = bytes.len();
    sum += len as u32;
    let mut i = 0;

    while i + 1 < len {
        sum += ((bytes[i] as u16) << 8 | (bytes[i + 1] as u16)) as u32;
        i += 2;
    }

    if len & 1 != 0 { sum += (bytes[len - 1] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum >> 16) + (sum & 65535); }
    !sum as u16
}

pub fn ipv4_checksum_v3(packet: &TcpPacket, ipv4_source: Ipv4Addr,
                     ipv4_destination: Ipv4Addr,
                     next_level_protocol: IpNextHeaderProtocol) -> u16 {
    let mut sum = 0;
    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    let mut sum = 0u32;
    let octets = ipv4_source.octets();
    sum += ((octets[0] as u16) << 8 | (octets[1] as u16)) as u32;
    sum += ((octets[2] as u16) << 8 | (octets[3] as u16)) as u32;

    let octets = ipv4_destination.octets();
    sum += ((octets[0] as u16) << 8 | (octets[1] as u16)) as u32;
    sum += ((octets[2] as u16) << 8 | (octets[3] as u16)) as u32;

    sum += next_level_protocol as u32;
    let bytes = packet.packet();
    let len = bytes.len();
    sum += len as u32;
    unsafe { csum_partial_folded(bytes.as_ptr(), len as u32, sum.to_be()) }
    // while sum >> 16 != 0 { sum = (sum >> 16) + (sum & 65535); }
    // !sum as u16
}

fn test(func: fn(packet: &TcpPacket, ipv4_source: Ipv4Addr,
                     ipv4_destination: Ipv4Addr,
                     next_level_protocol: IpNextHeaderProtocol) -> u16) {
    let ipv4_source = Ipv4Addr::new(192, 168, 2, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 111, 51);
    let next_level_protocol = IpNextHeaderProtocols::Tcp;

    let ref_packet =
            [193, 103, 35, 40, 144, 55, 210, 184, 148, 75, 178, 118, 128, 24, 15,
             175, 192, 49, 0, 0, 1, 1, 8, 10, 44, 87, 205, 165, 2, 160, 65, 146,
             116, 101, 115, 116];
    let packet = TcpPacket::new(&ref_packet[..]).unwrap();
    let before = Instant::now();
    for i in (0..1000000) {
         let sum = func(&packet, ipv4_source, ipv4_destination, next_level_protocol);
         if sum != 0 {
            println!("sum: {:X}", sum);
         }
         assert!(sum == 0);
    }
    println!("Elapsed: {:?}", before.elapsed());
}

/// Calculates the checksum of an IPv4 packet
pub fn ip_checksum_v1(packet: &Ipv4Packet) -> u16 {
    use pnet::packet::Packet;

    let len = packet.get_header_length() as usize * 4;
    let mut sum = 0u32;
    let mut i = 0;
    while i < len {
        let word = (packet.packet()[i] as u32) << 8 | packet.packet()[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

/// Calculates the checksum of an IPv4 packet
pub fn ip_checksum_v2(packet: &Ipv4Packet) -> u16 {
    use pnet::packet::Packet;

    let len = packet.get_header_length() as usize * 4;
    let mut sum = 0u32;
    let mut i = 0;
    let bytes = packet.packet();
    while i < len {
        let word = ((bytes[i] as u16) << 8 | bytes[i + 1] as u16) as u32;
        sum += word;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

pub fn ip_checksum_v3(packet: &Ipv4Packet) -> u16 {
    use pnet::packet::Packet;

    let len = packet.get_header_length() as usize * 4;
    let bytes = packet.packet();

    unsafe { ip_compute_csum(bytes.as_ptr(), len as u32) }
}

fn test_ip(func: fn(&Ipv4Packet) -> u16) {
    let ref_packet = [0x45,           /* ver/ihl */
                      0x11,           /* dscp/ecn */
                      0x00, 0x73,     /* total len */
                      0x01, 0x01,     /* identification */
                      0x41, 0x01,     /* flags/frag offset */
                      0x40,           /* ttl */
                      0x11,           /* proto */
                      0xb6, 0x4e,     /* checksum */
                      0xc0, 0xa8, 0x00, 0x01, /* source ip */
                      0xc0, 0xa8, 0x00, 0xc7  /* dest ip */];

    let ipv4 = Ipv4Packet::new(&ref_packet).unwrap();

    let packet = ipv4.to_immutable();
    let before = Instant::now();
    for i in (0..1000000) {
         let sum = func(&packet);
         if sum != 0 {
            println!("sum: {:X}", sum);
         }
         assert!(sum == 0);
    }
    println!("Elapsed: {:?}", before.elapsed());
}

fn main() {
    println!("TCP checksum");
    print!("v1: ");
    test(ipv4_checksum);

    print!("v2: ");
    test(ipv4_checksum_v2);

    print!("v3: ");
    test(ipv4_checksum_v3);

    println!("IP checksum");

    print!("v1: ");
    test_ip(ip_checksum_v1);

    print!("v2: ");
    test_ip(ip_checksum_v2);

    print!("v3: ");
    test_ip(ip_checksum_v3);
}
