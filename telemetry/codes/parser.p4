/********************************************************************
 * parsers and deparsers
 *******************************************************************/

/* indicate INT at LSB of DSCP */
const bit<6> DSCP_INT = 0x17;

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6 : parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.dscp) {
	    /* &&& is a mask operator in p4_16 */
            DSCP_INT &&& DSCP_INT: parse_intl4_shim;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        meta.update_udp_checksum = (hdr.udp.checksum != 0);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_INT: parse_intl4_shim;
            default: accept;
        }
    }
    state parse_intl4_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_header;
    }
    state parse_int_header {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }

    state parse_int_data {
        // Parse INT metadata, not INT header and INT shim header (length in bits)
        packet.extract(hdr.int_data, (bit<32>) ((hdr.intl4_shim.len - 3) << 5));
        transition accept;
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_port_tx_util);
        packet.emit(hdr.int_data);
    }
}