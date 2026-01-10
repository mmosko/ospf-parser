use hex_literal::hex;
use nom_derive::Parse;
use ospf_parser::*;
use std::net::Ipv4Addr;

#[test]
pub fn test_hello_packet() {
    // packet 6 of "ospf.cap" (wireshark samples)
    const OSPF_HELLO: &[u8] = &hex!(
        "
02 01 00 2c c0 a8 aa 08 00 00 00 01 27 3b 00 00
00 00 00 00 00 00 00 00 ff ff ff 00 00 0a 02 01
00 00 00 28 c0 a8 aa 08 00 00 00 00"
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_HELLO).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv2Packet::Hello(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::Hello);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.network_mask(), Ipv4Addr::new(255, 255, 255, 0));
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_db_description_packet() {
    // packet 10 of "ospf.cap" (wireshark samples)
    const OSPF_DBDESC: &[u8] = &hex!(
        "
        02 02 00 20 c0 a8 aa 08 00 00 00 01 a0 52 00 00
        00 00 00 00 00 00 00 00 05 dc 02 07 41 77 a9 7e
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_DBDESC).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv2Packet::DatabaseDescription(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::DatabaseDescription);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.if_mtu, 1500);
        assert_eq!(pkt.dd_sequence_number, 0x4177_a97e);
        assert_eq!(pkt.lsa_headers.len(), 0);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_db_description_packet_with_lsa() {
    // packet 12 of "ospf.cap" (wireshark samples)
    const OSPF_DBDESC: &[u8] = &hex!(
        "
        02 02 00 ac c0 a8 aa 03 00 00 00 01 f0 67 00 00
        00 00 00 00 00 00 00 00 05 dc 02 02 41 77 a9 7e
        00 01 02 01 c0 a8 aa 03 c0 a8 aa 03 80 00 00 01
        3a 9c 00 30 00 02 02 05 50 d4 10 00 c0 a8 aa 02
        80 00 00 01 2a 49 00 24 00 02 02 05 94 79 ab 00
        c0 a8 aa 02 80 00 00 01 34 a5 00 24 00 02 02 05
        c0 82 78 00 c0 a8 aa 02 80 00 00 01 d3 19 00 24
        00 02 02 05 c0 a8 00 00 c0 a8 aa 02 80 00 00 01
        37 08 00 24 00 02 02 05 c0 a8 01 00 c0 a8 aa 02
        80 00 00 01 2c 12 00 24 00 02 02 05 c0 a8 ac 00
        c0 a8 aa 02 80 00 00 01 33 41 00 24
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_DBDESC).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv2Packet::DatabaseDescription(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::DatabaseDescription);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 3));
        assert_eq!(pkt.if_mtu, 1500);
        assert_eq!(pkt.dd_sequence_number, 0x4177_a97e);
        assert_eq!(pkt.lsa_headers.len(), 7);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_request() {
    // packet 17 of "ospf.cap" (wireshark samples)
    const OSPF_LSREQ: &[u8] = &hex!(
        "
        02 03 00 24 c0 a8 aa 03 00 00 00 01 bd c7 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 08
        c0 a8 aa 08
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSREQ).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateRequest(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateRequest);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 3));
        assert_eq!(pkt.requests.len(), 1);
        let req0 = &pkt.requests[0];
        assert_eq!(req0.link_state_type, 1);
        assert_eq!(req0.link_state_id(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(req0.advertising_router(), Ipv4Addr::new(192, 168, 170, 8));
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_request_multiple_lsa() {
    // packet 18 of "ospf.cap" (wireshark samples)
    const OSPF_LSREQ_WITH_LSA: &[u8] = &hex!(
        "
        02 03 00 6c c0 a8 aa 08 00 00 00 01 75 95 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 03
        c0 a8 aa 03 00 00 00 05 50 d4 10 00 c0 a8 aa 02
        00 00 00 05 94 79 ab 00 c0 a8 aa 02 00 00 00 05
        c0 82 78 00 c0 a8 aa 02 00 00 00 05 c0 a8 00 00
        c0 a8 aa 02 00 00 00 05 c0 a8 01 00 c0 a8 aa 02
        00 00 00 05 c0 a8 ac 00 c0 a8 aa 02
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSREQ_WITH_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateRequest(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateRequest);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.requests.len(), 7);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_update() {
    // packet 19 of "ospf.cap" (wireshark samples)
    const OSPF_LSUPD: &[u8] = &hex!(
        "
        02 04 00 40 c0 a8 aa 08 00 00 00 01 96 1f 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 03 e2 02 01
        c0 a8 aa 08 c0 a8 aa 08 80 00 0d c3 25 06 00 24
        02 00 00 01 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSUPD).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateUpdate(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateUpdate);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.lsa.len(), 1);
        let lsa0 = &pkt.lsa[0];
        if let OspfLinkStateAdvertisement::RouterLinks(lsa) = lsa0 {
            assert_eq!(lsa.header.link_state_type, OspfLinkStateType::RouterLinks);
            assert_eq!(
                lsa.header.advertising_router(),
                Ipv4Addr::new(192, 168, 170, 8)
            );
            assert_eq!(lsa.links.len(), 1);
            let link0 = &lsa.links[0];
            assert_eq!(link0.link_id(), Ipv4Addr::new(192, 168, 170, 0));
            assert_eq!(link0.link_data(), Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(link0.link_type, OspfRouterLinkType::Stub);
            assert_eq!(link0.tos_list.len(), 0);
        } else {
            panic!("wrong LSA type");
        }
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_ack() {
    // packet 26 of "ospf.cap" (wireshark samples)
    const OSPF_LSACK: &[u8] = &hex!(
        "
        02 05 00 2c c0 a8 aa 08 00 00 00 01 02 f2 00 00
        00 00 00 00 00 00 00 00 00 01 02 01 c0 a8 aa 03
        c0 a8 aa 03 80 00 00 02 38 9d 00 30

        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSACK).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateAcknowledgment(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(
            pkt.header.packet_type,
            OspfPacketType::LinkStateAcknowledgment
        );
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.lsa_headers.len(), 1);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_update_multiple_lsa() {
    // packet 26 of "ospf.cap" (wireshark samples)
    const OSPF_LSA: &[u8] = &hex!(
        "
02 04 01 24 c0 a8 aa 03 00 00 00 01 36 6b 00 00
00 00 00 00 00 00 00 00 00 00 00 07 00 02 02 01
c0 a8 aa 03 c0 a8 aa 03 80 00 00 01 3a 9c 00 30
02 00 00 02 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
c0 a8 aa 00 ff ff ff 00 03 00 00 0a 00 03 02 05
50 d4 10 00 c0 a8 aa 02 80 00 00 01 2a 49 00 24
ff ff ff ff 80 00 00 14 00 00 00 00 00 00 00 00
00 03 02 05 94 79 ab 00 c0 a8 aa 02 80 00 00 01
34 a5 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 01
00 00 00 00 00 03 02 05 c0 82 78 00 c0 a8 aa 02
80 00 00 01 d3 19 00 24 ff ff ff 00 80 00 00 14
00 00 00 00 00 00 00 00 00 03 02 05 c0 a8 00 00
c0 a8 aa 02 80 00 00 01 37 08 00 24 ff ff ff 00
80 00 00 14 00 00 00 00 00 00 00 00 00 03 02 05
c0 a8 01 00 c0 a8 aa 02 80 00 00 01 2c 12 00 24
ff ff ff 00 80 00 00 14 00 00 00 00 00 00 00 00
00 03 02 05 c0 a8 ac 00 c0 a8 aa 02 80 00 00 01
33 41 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 0a
00 00 00 00
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateUpdate(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateUpdate);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 3));
        assert_eq!(pkt.lsa.len(), 7);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_lsa_summary() {
    // packet 12 of "OSPF_LSA_types.cap" (packetlife)
    const OSPF_LSA: &[u8] = &hex!(
        "
00 0b 22 03 c0 a8 0a 00 04 04 04 04 80 00 00 01
1e 7d 00 1c ff ff ff 00 00 00 00 1e
        "
    );

    let (rem, res) = OspfLinkStateAdvertisement::parse(OSPF_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let OspfLinkStateAdvertisement::SummaryLinkIpNetwork(lsa) = res {
        assert_eq!(lsa.header.link_state_id(), Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(lsa.header.advertising_router(), Ipv4Addr::new(4, 4, 4, 4));
        assert_eq!(lsa.metric, 30);
        assert_eq!(lsa.tos_routes.len(), 0);
    } else {
        panic!("wrong lsa type");
    }
}

#[test]
pub fn test_lsa_type7() {
    // packet 11 of "OSPF_type7_LSA.cap" (packetlife)
    const OSPF_LSA: &[u8] = &hex!(
        "
00 66 28 07 ac 10 00 00 02 02 02 02 80 00 00 01
63 ac 00 24 ff ff ff fc 80 00 00 64 c0 a8 0a 01
00 00 00 00
        "
    );

    let (rem, res) = OspfLinkStateAdvertisement::parse(OSPF_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let OspfLinkStateAdvertisement::NSSAASExternal(lsa) = res {
        assert_eq!(lsa.header.link_state_id(), Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(lsa.header.advertising_router(), Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(lsa.metric, 100);
        assert_eq!(lsa.forwarding_address(), Ipv4Addr::new(192, 168, 10, 1));
        assert_eq!(lsa.tos_list.len(), 0);
    } else {
        panic!("wrong lsa type");
    }
}

#[test]
pub fn test_link_state_request_with_auth() {
        let lsa_request_bytes: Vec<u8> = vec![
            0x2,        // version
            0x3,        // packet type
            0x0, 0x24,  // packet length (36)
            0x2, 0x2, 0x2, 0x2,     // router
            0x0, 0x0, 0x0, 0x0,     // area
            0x0, 0x0,               // checksum
            0x0, 0x2,               // au type
            0x0, 0x0, 0x1, 0x10,    // authentication
            0x69, 0xa, 0xc0, 0xb2,
            // -----
            0x0, 0x0, 0x0, 0x1,     // LS type
            0x1, 0x1, 0x1, 0x1,     // link state ID
            0x1, 0x1, 0x1, 0x1,     // adv. router
            // -----
            // signature
            0x98, 0x35, 0xda, 0x13, 0xd5, 0x3f, 0xe9, 0x51,
            0xd8, 0x40, 0xf4, 0xab, 0x10, 0x17, 0xc0, 0x2c];

    let (remaining, ospfv2_packet) = ospf_parser::parse_ospfv2_packet(&lsa_request_bytes).unwrap();
    let Ospfv2Packet::LinkStateRequest(lsa_request) = ospfv2_packet else {
        panic!("failed to parse Ospfv2");
    };
    assert_eq!(*remaining, lsa_request_bytes[36..52]);
    assert_eq!(lsa_request.requests.len(), 1);
}

#[test]
pub fn test_ospfv2_packet_header_display() {
    let header = Ospfv2PacketHeader {
        version: 2,
        packet_type: OspfPacketType::Hello,
        packet_length: 42,
        router_id: Ipv4Addr::new(10, 1, 1, 1).into(),
        area_id: 0,
        checksum: 0xABCD,
        au_type: 2,
        authentication: 0x0102030405060708,
    };
    let s = format!("{}", header);
    assert!(s.contains("version: 2"));
    assert!(s.contains("packet_type: Hello (1)"));
    assert!(s.contains("packet_length: 42"));
    assert!(s.contains("router_id: 10.1.1.1"));
    assert!(s.contains("area_id: 0.0.0.0"));
    assert!(s.contains("checksum: 0xABCD"));
    assert!(s.contains("au_type: 2"));
    assert!(s.contains("authentication: 0x0102030405060708"));
}

#[test]
pub fn test_ospf_hello_packet_display() {
    let header = Ospfv2PacketHeader {
        version: 2,
        packet_type: OspfPacketType::Hello,
        packet_length: 56,
        router_id: Ipv4Addr::new(10, 1, 1, 1).into(),
        area_id: 0,
        checksum: 0xABCD,
        au_type: 2,
        authentication: 0x0102030405060708,
    };
    let hello_packet = OspfHelloPacket {
        header,
        network_mask: Ipv4Addr::new(255, 255, 255, 0).into(),
        hello_interval: 10,
        options: 0x42,
        router_priority: 1,
        router_dead_interval: 40,
        designated_router: Ipv4Addr::new(10, 1, 1, 2).into(),
        backup_designated_router: Ipv4Addr::new(10, 1, 1, 3).into(),
        neighbor_list: vec![
            Ipv4Addr::new(10, 1, 1, 4).into(),
            Ipv4Addr::new(10, 1, 1, 5).into(),
        ],
    };
    let s = format!("{}", hello_packet);
    assert!(s.contains("network_mask: 255.255.255.0"));
    assert!(s.contains("options: 0x42"));
    assert!(s.contains("designated_router: 10.1.1.2"));
    assert!(s.contains("backup_designated_router: 10.1.1.3"));
    assert!(s.contains(r#"neighbor_list: [10.1.1.4, 10.1.1.5]"#));
}

#[test]
pub fn test_ospf_database_description_packet_display() {
    let header = Ospfv2PacketHeader {
        version: 2,
        packet_type: OspfPacketType::DatabaseDescription,
        packet_length: 68,
        router_id: Ipv4Addr::new(10, 1, 1, 1).into(),
        area_id: 0,
        checksum: 0xABCD,
        au_type: 2,
        authentication: 0x0102030405060708,
    };
    let lsa_header = OspfLinkStateAdvertisementHeader {
        ls_age: 3600,
        options: 0x42,
        link_state_type: OspfLinkStateType::RouterLinks,
        link_state_id: Ipv4Addr::new(10, 1, 1, 2).into(),
        advertising_router: Ipv4Addr::new(10, 1, 1, 1).into(),
        ls_seq_number: 0x80000001,
        ls_checksum: 0x1234,
        length: 20,
    };
    let db_packet = OspfDatabaseDescriptionPacket {
        header,
        if_mtu: 1500,
        options: 0x42,
        flags: 0x07,
        dd_sequence_number: 12345,
        lsa_headers: vec![lsa_header],
    };
    let s = format!("{}", db_packet);
    assert!(s.contains("if_mtu: 1500"));
    assert!(s.contains("options: 0x42"));
    assert!(s.contains("flags: 0x07"));
    assert!(s.contains("dd_sequence_number: 0x00003039"));
    assert!(s.contains("lsa_headers: ["));
    assert!(s.contains("ls_age: 3600"));
    assert!(s.contains("link_state_type: RouterLinks (1)"));
    assert!(s.contains("link_state_id: 10.1.1.2"));
    assert!(s.contains("advertising_router: 10.1.1.1"));
    assert!(s.contains("ls_seq_number: 0x80000001"));
    assert!(s.contains("ls_checksum: 0x1234"));
}

#[test]
pub fn test_ospf_link_state_request_packet_display() {
    let header = Ospfv2PacketHeader {
        version: 2,
        packet_type: OspfPacketType::LinkStateRequest,
        packet_length: 48,
        router_id: Ipv4Addr::new(10, 1, 1, 1).into(),
        area_id: 0,
        checksum: 0xABCD,
        au_type: 2,
        authentication: 0x0102030405060708,
    };
    let request = OspfLinkStateRequest {
        link_state_type: 1,
        link_state_id: Ipv4Addr::new(10, 1, 1, 2).into(),
        advertising_router: Ipv4Addr::new(10, 1, 1, 1).into(),
    };
    let req_packet = OspfLinkStateRequestPacket {
        header,
        requests: vec![request],
    };
    let s = format!("{}", req_packet);
    assert!(s.contains("requests: ["));
    assert!(s.contains("link_state_type: 1"));
    assert!(s.contains("link_state_id: 10.1.1.2"));
    assert!(s.contains("advertising_router: 10.1.1.1"));
}

#[test]
pub fn test_ospf_link_state_update_packet_display() {
    let header = Ospfv2PacketHeader {
        version: 2,
        packet_type: OspfPacketType::LinkStateUpdate,
        packet_length: 68,
        router_id: Ipv4Addr::new(10, 1, 1, 1).into(),
        area_id: 0,
        checksum: 0xABCD,
        au_type: 2,
        authentication: 0x0102030405060708,
    };
    let lsa_header = OspfLinkStateAdvertisementHeader {
        ls_age: 3600,
        options: 0x42,
        link_state_type: OspfLinkStateType::RouterLinks,
        link_state_id: Ipv4Addr::new(10, 1, 1, 2).into(),
        advertising_router: Ipv4Addr::new(10, 1, 1, 1).into(),
        ls_seq_number: 0x80000001,
        ls_checksum: 0x1234,
        length: 20,
    };
    let router_lsa = OspfRouterLinksAdvertisement {
        header: lsa_header,
        flags: 0,
        num_links: 0,
        links: vec![],
    };
    let lsu_packet = OspfLinkStateUpdatePacket {
        header,
        num_advertisements: 1,
        lsa: vec![OspfLinkStateAdvertisement::RouterLinks(router_lsa)],
    };
    let s = format!("{}", lsu_packet);
    assert!(s.contains("num_advertisements: 1"));
    assert!(s.contains("lsa: ["));
    assert!(s.contains("ls_age: 3600"));
}
