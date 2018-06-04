control Int_metadata_insert(inout headers hdr,
                            in    metadata meta,
                            in    standard_metadata_t standard_metadata)
{
    /* this reference implementation covers only INT instructions 0-3 */
    action int_set_header_0() {
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = meta.int_metadata.switch_id;
    }
    action int_set_header_1() {
        hdr.int_level1_port_ids.setValid();
        hdr.int_level1_port_ids.ingress_port_id =
            (bit<16>) standard_metadata.ingress_port;
        hdr.int_level1_port_ids.egress_port_id =
            (bit<16>) standard_metadata.egress_port;
    }
    action int_set_header_2() {
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency =
            (bit<32>) standard_metadata.deq_timedelta;
    }
    action int_set_header_3() {
        hdr.int_q_occupancy.setValid();
        // q_id not supported in v1model.
        hdr.int_q_occupancy.q_id = 0xff;
            // (bit<8>) standard_metadata.egress_qid;
        hdr.int_q_occupancy.q_occupancy =
            (bit<24>) standard_metadata.deq_qdepth;
    }

    /* action functions for bits 0-3 combinations, 0 is msb, 3 is lsb */
    /* Each bit set indicates that corresponding INT header should be added */
    action int_set_header_0003_i0() {
    }
    action int_set_header_0003_i1() {
        int_set_header_3();
    }
    action int_set_header_0003_i2() {
        int_set_header_2();
    }
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
    }
    action int_set_header_0003_i4() {
        int_set_header_1();
    }
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
    }
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i8() {
        int_set_header_0();
    }
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
    }
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }

    /* Table to process instruction bits 0-3 */
    table int_inst_0003 {
        key = {
            hdr.int_header.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        default_action = int_set_header_0003_i0();
        size = 16;
    }

    /* Similar tables can be defined for instruction bits 4-7 and bits 8-11 */
    /* e.g., int_inst_0407, int_inst_0811 */

    apply{
        int_inst_0003.apply();
        // int_inst_0407.apply();
        // int_inst_0811.apply();
    }
}

control Int_source_sink(inout headers hdr,
                        inout metadata meta,
                        in    standard_metadata_t standard_metadata)
{
    action send_postcard_report() {
        // Placeholder for postcard report generation.
        NoAction();
    }

    action int_sink() {
        // restore length fields of IPv4 header
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)(hdr.intl4_shim.len << 2);
        hdr.ipv4.dscp = (bit<6>)hdr.intl4_shim.dscp;
        // Restore TCP/UDP
        hdr.udp.length_ = hdr.udp.length_ - (bit<16>)(hdr.intl4_shim.len << 2);
        // remove all the INT information from the packet
        hdr.int_header.setInvalid();
        hdr.int_data.setInvalid();
        hdr.intl4_shim.setInvalid();
        hdr.int_switch_id.setInvalid();
        hdr.int_level1_port_ids.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_q_occupancy.setInvalid();
        hdr.int_ingress_tstamp.setInvalid();
        hdr.int_egress_tstamp.setInvalid();
        hdr.int_level2_port_ids.setInvalid();
        hdr.int_egress_port_tx_util.setInvalid();
    }

    action int_source(bit<8> remaining_hop_cnt, bit<5> hop_metadata_len,
        bit<4> ins_mask0003, bit<4> ins_mask0407, bit<4> ins_mask1215) {
        // insert INT shim header for TCP/UDP
        hdr.intl4_shim.setValid();
        // TODO: check the exact value for this field.
        // int_type: Hop-by-hop type (1) , destination type (2)
        // Destination type is not defined, therefore not supported in this implementation.
        hdr.intl4_shim.int_type = 1;
        /* Default INT header length in 4-byte words.
        (4 byte INT shim header + 8 byte INT metadata header) */
        hdr.intl4_shim.len = 3;
        hdr.intl4_shim.dscp = hdr.ipv4.dscp;

        // insert INT hop-by-hop metadata header
        hdr.int_header.setValid();
        // 1 for INT version 1.0
        hdr.int_header.ver = 1;
        hdr.int_header.rep = 0;
        hdr.int_header.c = 0;
        hdr.int_header.e = 0;
        hdr.int_header.m = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.rsvd2 = 0;
        hdr.int_header.hop_metadata_len = hop_metadata_len;
        hdr.int_header.remaining_hop_cnt = remaining_hop_cnt;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0; // not supported
        hdr.int_header.instruction_mask_1215 = ins_mask1215; // only checksum complement (bit 15) is supported

        // add the header len to total len
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12; // INT_HEADER_LEN_WORD (3)  * INT_WORD_SIZE (4);
        hdr.udp.length_ = hdr.udp.length_ + 12; // INT_HEADER_LEN_WORD (3) * INT_WORD_SIZE (4);

        // Set DSCP field to indicate the existance of INT header
        hdr.ipv4.dscp = DSCP_INT;
    }

    table tb_int_source {
        key = {}
        actions = {int_source;}
    }

    apply {
        if (meta.int_metadata.source == 1 && meta.int_metadata.last_hop == 1) {
            // This is 1-hop source/sink case, we can't add INT.
            // Generate postcard report instead.
            send_postcard_report();
        } else if (meta.int_metadata.source == 1){
            // This is source. Add INT header.
            tb_int_source.apply();
        } else if (hdr.int_header.isValid() && meta.int_metadata.last_hop == 1) {
            // This is sink. Strip out INT and generate INT report,
            // including metadata from this switch, and reset DSCP.
            int_sink();
        }
    }
}

control Int_transit(inout headers hdr,
                    inout metadata meta,
                    in    standard_metadata_t standard_metadata)
{
    action int_hop_cnt_exceeded() {
        hdr.int_header.e = 1;
    }

    action int_transit(bit<32> switch_id, bit<16> l3_mtu) {
        meta.int_metadata.switch_id = switch_id;
        meta.int_metadata.insert_byte_cnt =
            (bit<16>) hdr.int_header.hop_metadata_len << 2;
        meta.int_metadata.int_hdr_word_len =
            (bit<8>) hdr.int_header.hop_metadata_len;
        meta.fwd_metadata.l3_mtu = l3_mtu;
    }

    action int_mtu_limit_hit() {
        hdr.int_header.m = 1;
    }

    action int_hop_cnt_decrement() {
        hdr.int_header.remaining_hop_cnt =
            hdr.int_header.remaining_hop_cnt - 1;
    }

    action int_update_outer_encap() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + meta.int_metadata.insert_byte_cnt;
        hdr.intl4_shim.len = hdr.intl4_shim.len + meta.int_metadata.int_hdr_word_len;
        hdr.udp.length_ = hdr.udp.length_ + meta.int_metadata.insert_byte_cnt;
    }

    table int_prep {
        key = {}
        actions = {int_transit;}
    }

    Int_metadata_insert() int_metadata_insert;

    apply {
        // Add INT metadata, after header validation.
        if (hdr.int_header.remaining_hop_cnt == 0
            || hdr.int_header.e == 1) {
            // Remaining hop count exceeds. Set e bit and do not add metadata.
            int_hop_cnt_exceeded();
        } else if ((hdr.int_header.instruction_mask_0811 ++
                    hdr.int_header.instruction_mask_1215)
                    & 8w0xFE == 0 ) {
            /* v1.0 spec allows two options for handling unsupported
            * INT instructions. This exmple code skips the entire
            * hop if any unsupported bit (bit 8 to 14 in v1.0 spec) is set.
            */
            int_prep.apply();

            // check MTU limit
            if (hdr.ipv4.totalLen + meta.int_metadata.insert_byte_cnt
                > meta.fwd_metadata.l3_mtu) {
                // MTU limit will exceed. Set m bit and do not add INT metadata.
                int_mtu_limit_hit();
            } else {
                // Add INT metadata and update INT shim header and outer headers.
                int_hop_cnt_decrement();
                int_metadata_insert.apply(hdr, meta, standard_metadata);
                int_update_outer_encap();
            }
        }
    }
}

control Int_ingress(inout headers hdr,
                    inout metadata meta,
                    in    standard_metadata_t standard_metadata)
{
    action int_set_first_hop () {
        meta.int_metadata.first_hop = 1;
    }
    action int_set_source () {
        meta.int_metadata.source = 1;
    }
    action int_check() {
        meta.int_metadata.int_check = 1;
    }
    action clear_int_bit () {
        hdr.ipv4.dscp = 0;
    }
    table tb_set_first_hop {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {int_set_first_hop;}
    }

    table tb_set_source {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.tcp.srcPort:  ternary;
            hdr.tcp.dstPort:  ternary;
            hdr.udp.srcPort:  ternary;
            hdr.udp.dstPort:  ternary;
        }
        actions = {int_set_source;}
    }

    apply{
        // Determine whether this switch acts as a source or not for a given packet.
        // (Acts as a source when a packet is coming from a host.)
        tb_set_first_hop.apply();
        if (meta.int_metadata.first_hop == 1) {
            if (hdr.ipv4.dscp == DSCP_INT) {
                // If hdr.ipv4.dscp was received as DSCP_INT, coming from a host,
                // it will be considered as Invalid state. Clear out the INT bit.
                clear_int_bit();
            }
            // Specify traffic slice to apply INT, as a 5-tuple.
            tb_set_source.apply();
        } else {
            // Metadata to indicate egress parser to parse INT header.
            // Parse INT header at egress parser only if
            // hdr.ipv4.dscp == DSCP_INT and this metadata is set.

            // Since v1model only has a single parser at ingress,
            // this action will have no effect.
            int_check();
        }
     }
 }

control Int_egress(inout headers hdr,
                   inout metadata meta,
                   in    standard_metadata_t standard_metadata)
{
    action int_set_last_hop() {
        meta.int_metadata.last_hop = 1;
    }

    table tb_set_last_hop {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {int_set_last_hop;}
    }

    Int_transit() int_transit;
    Int_source_sink() int_source_sink;

    apply{
        /* INT processing is only applied to packets with valid TCP or UDP header,
         * and not coming from or going to CPU_PORT.
         */
        if (standard_metadata.ingress_port != CPU_PORT &&
            standard_metadata.egress_port != CPU_PORT &&
            (hdr.udp.isValid() || hdr.tcp.isValid())) {
            // Determine whether this switch acts as a sink or not for a given packet.
            // (Acts as a sink when a packet is being forwarded to a host.)
            tb_set_last_hop.apply();

            // Manipulate a packet, as source or sink
            int_source_sink.apply(hdr, meta, standard_metadata);

            // Manipulate a packet, as transit
            if (hdr.int_header.isValid()) {
                int_transit.apply(hdr, meta, standard_metadata);
            }
        }
    }
}
