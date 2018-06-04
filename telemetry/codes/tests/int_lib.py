#!/usr/bin/env python2

from scapy.packet import Packet
from scapy.fields import BitField, ShortField, XByteField, IntField
import ptf.testutils as testutils

class INT_SHIM_HDR(Packet):
    name = "INT_SHIM_HDR"
    fields_desc = [ XByteField("int_type", 0x01),
                    XByteField("rsvd0", 0x00),
                    XByteField("length", 0x03),
                    BitField("DSCP", 0, 6),
                    BitField("rsvd1", 0, 2) ]

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 1, 4), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField( "m", 0, 1 ), BitField("rsvd1", 0, 7),
                    BitField( "rsvd2", 0, 3 ), BitField("hop_ml", 1, 5),
                    BitField("remaining_hop_cnt", 0xF, 8),
                    ShortField("inst_mask", 0x8000),
                    ShortField("rsvd2", 0x0000)]

# INT data header
class INT_HOP_INFO(Packet):
    name = "INT_hop_info"
    fields_desc = [ IntField("val", 0xFFFFFFFF) ]

DSCP_INT = 0x17

def mask( length ):
    if length > 0:
        return (chr( int( '1' * (length % 8), 2 ) ) if length % 8 > 0 else '') + \
               '\xff' * (length / 8)
    else:
        return ''

def expected_pkt(packet):
    return packet.__class__(str(packet))

def udp_payload_str(length):
    return ("".join( [ chr( x % 256 ) for x in xrange(length) ] ))

def int_udp_packet(pktlen=200,
                   eth_dst='00:01:02:03:04:05',
                   eth_src='00:06:07:08:09:0a',
                   ip_dst='10.10.10.1',
                   ip_src='192.168.0.1',
                   udp_sport=101,
                   udp_dport=4790,
                   with_udp_chksum=False,
                   int_remaining_hop_cnt=64,
                   int_inst_mask=0x8000,
                   int_metadata_stack=[]):
    pkt = testutils.simple_udp_packet(
        pktlen=0,
        eth_dst=eth_dst,
        eth_src=eth_src,
        ip_dst=ip_dst,
        ip_src=ip_src,
        ip_dscp=DSCP_INT,
        udp_sport=udp_sport,
        udp_dport=udp_dport,
        with_udp_chksum=with_udp_chksum
    )

    int_hdr = build_int_hdr(int_remaining_hop_cnt=int_remaining_hop_cnt,
                            int_inst_mask=int_inst_mask,
                            int_metadata_stack=int_metadata_stack)
    pkt /= int_hdr
    pkt /= ("".join( [ chr( x % 256 ) for x in xrange( pktlen - len( pkt ) ) ] ))
    return pkt

def build_int_hdr(int_remaining_hop_cnt=64,
                  int_inst_mask=0x8000,
                  int_metadata_stack=[]):
    int_hop_ml = bin(int_inst_mask).count("1")
    int_shim_hdr = INT_SHIM_HDR(length=3+len(int_metadata_stack)) # this header(4) + INT meta header (8)
    int_meta_hdr = INT_META_HDR(hop_ml=int_hop_ml,
                                remaining_hop_cnt=int_remaining_hop_cnt,
                                inst_mask=int_inst_mask)
    pkt = int_shim_hdr / int_meta_hdr
    for metadata in int_metadata_stack:
        pkt /= INT_HOP_INFO( val=metadata )

    return pkt
