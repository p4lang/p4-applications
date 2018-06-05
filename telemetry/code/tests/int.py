#!/usr/bin/env python2

import sys
import ptf.testutils as testutils
from base_test import P4RuntimeTest, autocleanup, stringify, ipv4_to_binary
from int_lib import *

try:
    import scapy.config
    import scapy.route
    import scapy.layers.l2
    import scapy.layers.inet
    import scapy.main
except ImportError:
    sys.exit("Need to install scapy for packet parsing")

class Params:
    ip_src_addr = "10.0.0.1"
    ip_dst_addr = "10.0.1.1"
    l4_sport = 1000
    l4_dport = 80
    ip_src_addr_str = ipv4_to_binary( ip_src_addr )
    ip_dst_addr_str = ipv4_to_binary( ip_dst_addr )
    # port is 9-bit in v1model, i.e. 2 bytes
    l4_sport_str = stringify( l4_sport, 2 )
    l4_dport_str = stringify( l4_dport, 2 )
    pkt_len=200

    # INT-related parameters
    remaining_hop_cnt = 64
    hop_ml = 1
    ins_mask0003 = 8
    ins_mask0407 = 0
    ins_mask1215 = 0
    ins_mask = 0x8000
    sw_id_list = range( 100, 200 )
    mtu = 1500
    remaining_hop_cnt_str = stringify( remaining_hop_cnt, 1 )
    hop_ml_str = stringify( hop_ml, 1 )
    ins_mask0003_str = stringify( ins_mask0003, 1 )
    ins_mask0407_str = stringify( ins_mask0407, 1 )
    ins_mask1215_str = stringify( ins_mask1215, 1 )
    sw_id_str_list = [ stringify( sw_id, 4 ) for sw_id in sw_id_list ]
    mtu_str = stringify( mtu, 2 )

class IntForwardingTest(P4RuntimeTest):
    # Test to verify basic forwarding function is working.
    # Other INT tests are relying on the basic forwarding.
    @autocleanup
    def runTest( self ):
        ig_port = self.swports(1)
        eg_port = self.swports(2)
        # port is 9-bit in v1model, i.e. 2 bytes
        ig_port_str = stringify(ig_port, 2)
        eg_port_str = stringify(eg_port, 2)

        pkt = testutils.simple_tcp_packet(pktlen=Params.pkt_len,
                                          ip_src=Params.ip_src_addr,
                                          ip_dst=Params.ip_dst_addr,
                                          ip_ihl=5
                                          )
        # Add forwarding entry
        self.send_request_add_entry_to_action(
            "table0",
            [self.Ternary("standard_metadata.ingress_port", ig_port_str, mask(9)),
             self.Ternary( "hdr.ipv4.srcAddr", Params.ip_src_addr_str, mask(32) ),
             self.Ternary( "hdr.ipv4.dstAddr", Params.ip_dst_addr_str, mask(32) )],
            "set_egress_port",
            [("port", eg_port_str)])
        # check that the entry is hit and that no other packets are received
        exp_pkt = testutils.simple_tcp_packet(pktlen=Params.pkt_len,
                                              ip_src=Params.ip_src_addr,
                                              ip_dst=Params.ip_dst_addr,
                                              ip_ihl=5)
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_packets(self, expected_pkt(exp_pkt), [eg_port])

class IntSourceTest(P4RuntimeTest):
    # test INT header is correctly built
    @autocleanup
    def runTest( self ):
        ig_port = self.swports( 1 )
        eg_port = self.swports( 2 )
        ig_port_str = stringify( ig_port, 2 )
        eg_port_str = stringify( eg_port, 2 )
        pkt = testutils.simple_udp_packet(pktlen=Params.pkt_len,
                                          ip_src=Params.ip_src_addr,
                                          ip_dst=Params.ip_dst_addr,
                                          udp_sport=Params.l4_sport,
                                          udp_dport=Params.l4_dport,
                                          with_udp_chksum=False)
        # Add forwarding entry
        self.send_request_add_entry_to_action(
            "table0",
            [self.Ternary("standard_metadata.ingress_port", ig_port_str, mask(9)),
             self.Ternary( "hdr.ipv4.srcAddr", Params.ip_src_addr_str, mask(32) ),
             self.Ternary( "hdr.ipv4.dstAddr", Params.ip_dst_addr_str, mask(32) )],
            "set_egress_port",
            [("port", eg_port_str)])

        self.send_request_add_entry_to_action(
            "tb_set_first_hop",
            [self.Exact("standard_metadata.ingress_port", ig_port_str)],
            "int_set_first_hop",
            [])
        self.send_request_add_entry_to_action(
            "tb_set_source",
            [self.Ternary("hdr.ipv4.srcAddr", Params.ip_src_addr_str, mask(32)),
             self.Ternary("hdr.ipv4.dstAddr", Params.ip_dst_addr_str, mask(32)),
             self.Ternary( "hdr.udp.srcPort", Params.l4_sport_str, mask(16)),
             self.Ternary("hdr.udp.dstPort", Params.l4_dport_str, mask(16))],
            "int_set_source",
            [])

        self.send_request_add_entry_to_action(
            "tb_int_source",
            [],
            "int_source",
            [("remaining_hop_cnt", Params.remaining_hop_cnt_str),
             ("hop_metadata_len", Params.hop_ml_str),
             ("ins_mask0003", Params.ins_mask0003_str),
             ("ins_mask0407", Params.ins_mask0407_str),
             ("ins_mask1215", Params.ins_mask1215_str)])

        self.send_request_add_entry_to_action(
            "int_prep",
            [],
            "int_transit",
            [("switch_id", Params.sw_id_str_list[0]), ("l3_mtu", Params.mtu_str)])

        self.send_request_add_entry_to_action(
            "int_inst_0003",
            [self.Exact("hdr.int_header.instruction_mask_0003", Params.ins_mask0003_str)],
            "int_set_header_0003_i8",
            [])

        # check that the INT shim header and metadata header is correctly built
        exp_pkt = int_udp_packet(pktlen=Params.pkt_len + 16,
                                 ip_src=Params.ip_src_addr,
                                 ip_dst=Params.ip_dst_addr,
                                 udp_sport=Params.l4_sport,
                                 udp_dport=Params.l4_dport,
                                 with_udp_chksum=False,
                                 int_remaining_hop_cnt=Params.remaining_hop_cnt - 1,
                                 int_metadata_stack=[Params.sw_id_list[0],])
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_packets(self, expected_pkt(exp_pkt), [eg_port])

class IntTransitTest(P4RuntimeTest):
    # test INT shim header and metadata header are updated correctly, and
    # specified metadata is correctly added.
    @autocleanup
    def runTest( self ):
        ig_port = self.swports( 1 )
        eg_port = self.swports( 2 )
        ig_port_str = stringify( ig_port, 2 )
        eg_port_str = stringify( eg_port, 2 )
        pkt = int_udp_packet(pktlen=Params.pkt_len,
                             ip_src=Params.ip_src_addr,
                             ip_dst=Params.ip_dst_addr,
                             udp_sport=Params.l4_sport,
                             udp_dport=Params.l4_dport,
                             with_udp_chksum=False,
                             int_inst_mask=Params.ins_mask,
                             int_remaining_hop_cnt=Params.remaining_hop_cnt,
                             int_metadata_stack=[Params.sw_id_list[0],])
        # Add forwarding entry
        self.send_request_add_entry_to_action(
            "table0",
            [self.Ternary("standard_metadata.ingress_port", ig_port_str, mask(9)),
             self.Ternary( "hdr.ipv4.srcAddr", Params.ip_src_addr_str, mask(32) ),
             self.Ternary( "hdr.ipv4.dstAddr", Params.ip_dst_addr_str, mask(32) )],
            "set_egress_port",
            [("port", eg_port_str)])
        self.send_request_add_entry_to_action(
            "int_prep",
            [ ],
            "int_transit",
            [ ("switch_id", Params.sw_id_str_list[1]), ("l3_mtu", Params.mtu_str) ] )

        self.send_request_add_entry_to_action(
            "int_inst_0003",
            [self.Exact("hdr.int_header.instruction_mask_0003", Params.ins_mask0003_str) ],
            "int_set_header_0003_i8",
            [])

        # check that the INT shim header and metadata header is correctly built
        exp_pkt = int_udp_packet(pktlen=Params.pkt_len + 4,
                                 ip_src=Params.ip_src_addr,
                                 ip_dst=Params.ip_dst_addr,
                                 udp_sport=Params.l4_sport,
                                 udp_dport=Params.l4_dport,
                                 with_udp_chksum=False,
                                 int_remaining_hop_cnt=Params.remaining_hop_cnt - 1,
                                 int_metadata_stack=[ Params.sw_id_list[ 1 ], Params.sw_id_list[ 0 ] ] )
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_packets(self, expected_pkt(exp_pkt), [eg_port])

class IntSinkTest(P4RuntimeTest):
    # test whether sink switch correctly strip INT shim header, metadata header and metadata stack
    # and restore original packet.
    @autocleanup
    def runTest( self ):
        ig_port = self.swports( 1 )
        eg_port = self.swports( 2 )
        ig_port_str = stringify( ig_port, 2 )
        eg_port_str = stringify( eg_port, 2 )
        pkt = int_udp_packet(pktlen=Params.pkt_len,
                             ip_src=Params.ip_src_addr,
                             ip_dst=Params.ip_dst_addr,
                             udp_sport=Params.l4_sport,
                             udp_dport=Params.l4_dport,
                             with_udp_chksum=False,
                             int_inst_mask=Params.ins_mask,
                             int_remaining_hop_cnt=Params.remaining_hop_cnt,
                             int_metadata_stack=Params.sw_id_list[:2])
        # Add forwarding entry
        self.send_request_add_entry_to_action(
            "table0",
            [self.Ternary("standard_metadata.ingress_port", ig_port_str, mask(9)),
             self.Ternary( "hdr.ipv4.srcAddr", Params.ip_src_addr_str, mask(32) ),
             self.Ternary( "hdr.ipv4.dstAddr", Params.ip_dst_addr_str, mask(32) )],
            "set_egress_port",
            [("port", eg_port_str)])

        self.send_request_add_entry_to_action(
            "int_prep",
            [ ],
            "int_transit",
            [ ("switch_id", Params.sw_id_str_list[2]), ("l3_mtu", Params.mtu_str) ] )

        self.send_request_add_entry_to_action(
            "int_inst_0003",
            [self.Exact("hdr.int_header.instruction_mask_0003", Params.ins_mask0003_str) ],
            "int_set_header_0003_i8",
            [])

        self.send_request_add_entry_to_action(
            "tb_set_last_hop",
            [self.Exact("standard_metadata.egress_port", eg_port_str)],
            "int_set_last_hop",
            [])

        # check that the original UDP packet is correctly restored.
        exp_pkt = testutils.simple_udp_packet(pktlen=Params.pkt_len - 20,
                                              ip_src=Params.ip_src_addr,
                                              ip_dst=Params.ip_dst_addr,
                                              udp_sport=Params.l4_sport,
                                              udp_dport=Params.l4_dport,
                                              with_udp_chksum=False)
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_packets(self, expected_pkt(exp_pkt), [eg_port])
