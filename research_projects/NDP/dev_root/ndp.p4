/*******************************************************************************
 *
 * Copyright (c) 2020-2021 Correct Networks, Intel Corporation
 * All Rights Reserved.
 * Authors:
 * Dragos Dumitrescu (dragos@correctnetworks.io)
 * Adrian Popa (adrian.popa@correctnetworks.io)
 *
 * NOTICE: TBD
 *
 *
 ******************************************************************************/

/*******************************************************************************
 *
 * Here are the main steps:
 *
 * on ingress
 * the packet undergoes regular ipv4 forwarding with fwd decision to port egport
 * 1) if packet is ndp control => output packet to HIGH_PRIORITY_QUEUE
 * 2) if packet is ndp data => pass packet through meter[egport]
     2.1) if meter color is GREEN => output packet to LOW_PRIORITY_QUEUE
     2.2) if meter color != GREEN => clone packet to sid where (sid maps to egport, HIGH_PRIORITY_QUEUE,
          packet length = 80B)
   3) if packet is not ndp => proceed with forwarding on OTHERS_QUEUE
 *
 * on egress:
 *   1) if packet is ndp data and comes in from DoD port (dropped due to congestion)
     2) when trimmed or normal packets come in => do rewrites (mac src and dst addresses) and set ndp trim flags
     3) when clone packet back to egress to sesssion esid (esid maps to recirculation port, HIGH_PRIORITY_QUEUE, packet length = 80B)
     4) when packet comes back from egress clone => forward as-is (i.e. recirculate back into ingress) and notify all pipelines
        to transition into pessimistic mode

 * NDP modes:
 * Each egress port works in 3 modes:
   - optimistic
   - pessimistic
   - halftimistic
  The mode decides what meter will be used for NDP packets going out on the given port
   In optimistic, we use meter_optimistic (line-rate)
   In pessimistic, we use meter_pessimistic (1/4 * line-rate)
   In halftimistic, we use meter_halftimistic (1/2 * line-rate)

 Initially, the switch starts in optimistic mode for all ports
 Whenever a DoD packet is received in egress => all ingress pipelines are notified to
 trim more aggressively (i.e. transition into pessimistic mode).

 A port remains in pessimistic mode for T0 ns if no extra DoDs occur.
 After T0 ns, the port transitions into halftimistic mode.

 A port remains in halftimistic mode for T1 ns if no other DoDs occur.
 After T1 ns, the port transitions back into optimistic mode.
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/util.p4"
#include "common/headers.p4"


#ifndef T0_NS
#define T0_NS 6 * 1000
#endif

#ifndef T1_NS
#define T1_NS 24 * 1000
#endif

typedef bit<2> pkt_color_t;
typedef bit<32> ndp_timestamp_t;

const pkt_color_t SWITCH_METER_COLOR_GREEN = 0;
const pkt_color_t SWITCH_METER_COLOR_YELLOW = 1;
const pkt_color_t SWITCH_METER_COLOR_RED = 2;

const bit<32> ecmp_selection_table_size = 16384;
const bit<32> ecmp_table_size = 1024;

struct qos_metadata_a_t {
    pkt_color_t color;
}

struct ig_metadata_t {
    pkt_type_t pkt_type;
    PortId_t egress_port;
    MirrorId_t mirror_session_id;
    bool drop_ndp;
    bool always_truncate;
    ipv4_addr_t nhop;
    switch_lookup_fields_t lkp;
    bit<32> hash;
    bit<32> nhop_idx;
}
struct egress_metadata_t {
    MirrorId_t mirror_session_id;
    bit<1> is_recirculate_port;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    value_set<bit<9>>(4) is_recirc_port;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition select(ig_intr_md.ingress_port) {
           is_recirc_port : parse_update_command;
           default : parse_ethernet;
        }
    }
    state parse_update_command {
        pkt_type_t pktype = pkt.lookahead<pkt_type_t>();
        transition select(pktype) {
            PKT_TYPE_TRIM : parse_trim;
            PKT_TYPE_MIRROR_UPDATE : parse_update;
            PKT_TYPE_NOTIFY : parse_trim;
        }
    }
    state parse_update {
        pkt.extract(hdr.update_meta);
        transition parse_ethernet;
    }
    state parse_trim {
        pkt.extract<trim_metadata_t>(hdr.trim_meta);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TCP : parse_tcp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            666   : parse_ndp;
            default : accept;
        }
    }

    state parse_ndp {
        ndp_flags_t flags = pkt.lookahead<ndp_flags_t>();
        transition select(flags[3:1]) {
            3w0b100 &&& 3w0b100 : parse_ndp_s_ctrl;
            3w0b010 &&& 3w0b010 : parse_ndp_s_ctrl;
            3w0b001 &&& 3w0b001 : parse_ndp_s_ctrl;
            default: parse_ndp_s_data;
        }
    }

    state parse_ndp_s_data {
        pkt.extract(hdr.ndp_s_data);
        transition accept;
    }

    state parse_ndp_s_ctrl {
        pkt.extract(hdr.ndp_s_ctrl);
        transition accept;
    }

}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr, out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_metas;
    }
    state parse_metas {
        pkt_type_t pkttype = pkt.lookahead<pkt_type_t>();
        // egress parser drops by default
        transition select (pkttype) {
            PKT_TYPE_MIRROR : parse_mirror_md;
            PKT_TYPE_NORMAL : parse_normal_md;
            PKT_TYPE_TRIM : parse_trim;
            PKT_TYPE_MIRROR_UPDATE : parse_mirror_update;
            PKT_TYPE_NOTIFY : parse_trim;
        }
    }
    state parse_trim {
        pkt.extract<trim_metadata_t>(hdr.trim_meta);
        transition select(hdr.trim_meta.pkt_type) {
            PKT_TYPE_NOTIFY: parse_mirror_update;
            default: parse_ethernet;
        }
    }
    state parse_mirror_update {
        pkt.extract<update_packet_metadata_t>(hdr.update_meta);
        transition parse_ethernet;
    }
    state parse_normal_md {
        pkt.extract<normal_metadata_t>(hdr.normal_meta);
        transition parse_ethernet;
    }
    state parse_mirror_md {
        pkt.extract<eg_metadata_t>(hdr.egmeta);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            666   : parse_ndp;
            default : accept;
        }
    }

    state parse_ndp {
        ndp_flags_t flags = pkt.lookahead<ndp_flags_t>();
        transition select(flags[3:1]) {
            3w0b100 &&& 3w0b100 : parse_ndp_s_ctrl;
            3w0b010 &&& 3w0b010 : parse_ndp_s_ctrl;
            3w0b001 &&& 3w0b001 : parse_ndp_s_ctrl;
            default: parse_ndp_s_data;
        }
    }

    state parse_ndp_s_data {
        pkt.extract(hdr.ndp_s_data);
        transition accept;
    }

    state parse_ndp_s_ctrl {
        pkt.extract(hdr.ndp_s_ctrl);
        transition accept;
    }
}

header empty_hdr_t { }

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    Mirror() mirror;
    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

        if (ig_intr_dprsr_md.mirror_type == 3w1) {
            // emit with no data
            // does not work because of compiler bug in 8.9.1
            // mirror.emit(ig_md.mirror_session_id);
            mirror.emit<eg_metadata_t>(ig_md.mirror_session_id, hdr.egmeta);
        }
        if (ig_intr_dprsr_md.mirror_type == 3w2) {
            mirror.emit<trim_metadata_t>(ig_md.mirror_session_id, {ig_md.pkt_type, ig_md.egress_port, 0});
        }
        pkt.emit(hdr);
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {
    Checksum() ipv4_checksum;
    Mirror() mirror;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});
        pkt.emit(hdr);
        if (eg_intr_dprsr_md.mirror_type == 3w1) {
            mirror.emit<empty_h>(eg_md.mirror_session_id, {});
        }
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    bit<1> allow_pessimism;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS_AND_BYTES) per_port_counter;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) meter_chop;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) return_chop;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) nr_arm;

    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) nr_opti;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) nr_pesi;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) nr_half;

    // NDP switch state machine
    // for each egress port we maintain the following state machine:
    // s0(optimistic) : meter is at line-rate
    // s1(pessimistic) : meter is at 1/4 * line-rate
    // s2(1/2 pessimistic): meter is at 1/2 * line-rate
    // Transitions:
    // e1: s0 ------DoD------------> s1
    // e2: s1 ------t0 ns elapsed since e1 ----> s2
    // e3: s2 ------t1 ns elapsed since e1 ----> s0
    // on e1: set downgrade_time[port] = now();
    // on e3: set downgrade_time[port] = 0;
    // initially: port is in s0
    Register<ndp_timestamp_t, PortId_t>(32w256, 32w0) t0_reg;
    RegisterAction<ndp_timestamp_t, PortId_t, bit<1>>(t0_reg) arm0 = {
        void apply(inout ndp_timestamp_t v) {
            v = ig_intr_prsr_md.global_tstamp[31:0] + T0_NS;
        }
    };

    Register<ndp_timestamp_t, PortId_t>(32w256, 32w0) t1_reg;
    RegisterAction<ndp_timestamp_t, PortId_t, bit<1>>(t1_reg) arm1 = {
        void apply(inout ndp_timestamp_t v) {
            v = ig_intr_prsr_md.global_tstamp[31:0] + T1_NS;
        }
    };

    RegisterAction<ndp_timestamp_t, PortId_t, bit<1>>(t0_reg) transition_0 = {
        void apply(inout ndp_timestamp_t v, out bit<1> ret) {
            if (ig_intr_prsr_md.global_tstamp[31:0] > v) {
                v = 32w0;
                ret = 1w0;
            } else if (ig_intr_prsr_md.global_tstamp[31:0] + T0_NS < v) {
                v = 32w0;
                ret = 1w0;
            } else {
                ret = 1w1;
            }
        }
    };
    RegisterAction<ndp_timestamp_t, PortId_t, bit<1>>(t1_reg) transition_1 = {
        void apply(inout ndp_timestamp_t v, out bit<1> ret) {
            if (ig_intr_prsr_md.global_tstamp[31:0] > v) {
                v = 32w0;
                ret = 1w0;
            } else if (ig_intr_prsr_md.global_tstamp[31:0] + T1_NS < v) {
                v = 32w0;
                ret = 1w0;
            } else {
                ret = 1w1;
            }
        }
    };

    qos_metadata_a_t qos_md;
    Meter<PortId_t>(512, MeterType_t.BYTES) meter_optimistic;
    Meter<PortId_t>(512, MeterType_t.BYTES) meter_pessimistic;
    Meter<PortId_t>(512, MeterType_t.BYTES) meter_halftimistic;

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action ipv4_forward_direct_connect(mac_addr_t srcAddr, PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
        ig_md.egress_port = port;
        ig_md.nhop = hdr.ipv4.dst_addr;
        hdr.ethernet.src_addr = srcAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action ipv4_forward(mac_addr_t srcAddr, ipv4_addr_t nhop, PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
        ig_md.egress_port = port;
        ig_md.nhop = nhop;
        hdr.ethernet.src_addr = srcAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_nhop_idx(bit<32> nhop_idx) {
        ig_md.nhop_idx = nhop_idx;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            set_nhop_idx;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    action set_dst(mac_addr_t dst_addr) {
        hdr.ethernet.dst_addr = dst_addr;
    }
    table arp {
        key = {
            ig_md.nhop : exact;
        }
        actions = {
            drop;
            set_dst;
        }
        default_action = drop();
        size = 8192;
    }

    action set_high_priority() {
        ig_intr_tm_md.qid = 1;
    }

    action setup_metas_for_egress() {
        ig_intr_tm_md.qid = 0;
        ig_intr_tm_md.bypass_egress = 0;
    }
    // send normal packet to egress for further processing.
    // this action is applied against an NDP data packet
    // (regardless of whether it was trimmed or not)
    action set_low_priority() {
        hdr.normal_meta.setValid();
        hdr.normal_meta.pkt_type = PKT_TYPE_NORMAL;
        hdr.normal_meta.egress_port = ig_intr_tm_md.ucast_egress_port;
        // only DoD full ndp packets
        ig_intr_tm_md.deflect_on_drop = 1w1;
        setup_metas_for_egress();
    }

    action mirror_and_drop(MirrorId_t session_id) {
        ig_intr_dprsr_md.mirror_type = 3w1;
        ig_md.mirror_session_id = session_id;
        hdr.egmeta.setValid();
        hdr.egmeta.pkt_type = PKT_TYPE_MIRROR;
        hdr.egmeta.dstAddr = hdr.ethernet.dst_addr;
        hdr.egmeta.srcAddr = hdr.ethernet.src_addr;
        setup_metas_for_egress();
        drop();
    }

    table truncate {
        key = {
            ig_intr_tm_md.ucast_egress_port : exact;
        }
        actions = {
            mirror_and_drop;
            drop;
        }
        const default_action = drop();
        size = 512;
    }

    action set_config(bit<1> p_allow_pessimism, bit<1> always_truncate,
                      bit<1> drop_ndp) {
        allow_pessimism = p_allow_pessimism;
        ig_md.always_truncate = (bool)always_truncate;
        ig_md.drop_ndp = (bool)drop_ndp;
    }
    table configure_ndp {
        actions = {
            set_config;
        }
    }

    action set_lkp_ip() {
        ig_md.lkp.ip_src_addr = (bit<128>)hdr.ipv4.src_addr;
        ig_md.lkp.ip_dst_addr = (bit<128>)hdr.ipv4.dst_addr;
        ig_md.lkp.ip_proto = hdr.ipv4.protocol;
    }
    action set_lkp_udp() {
        set_lkp_ip();
        ig_md.lkp.l4_src_port = hdr.udp.src_port;
        ig_md.lkp.l4_dst_port = hdr.udp.dst_port;
    }
    action set_lkp_ndp() {
        set_lkp_ip();
        ig_md.lkp.l4_src_port = hdr.ndp_s_data.rsvd;
        ig_md.lkp.l4_dst_port = hdr.udp.dst_port;
    }
    action set_lkp_tcp() {
        set_lkp_ip();
        ig_md.lkp.l4_src_port = hdr.tcp.src_port;
        ig_md.lkp.l4_dst_port = hdr.tcp.dst_port;
    }
    action set_lkp_ip_unknown() {
        set_lkp_ip();
        ig_md.lkp.l4_src_port = hdr.udp.src_port;
        ig_md.lkp.l4_dst_port = hdr.udp.dst_port;
    }
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) selector_hash;
    ActionProfile(ecmp_selection_table_size) ecmp_selector;
    ActionSelector(
        ecmp_selector,
        selector_hash,
        SelectorMode_t.FAIR,
        16,
        ecmp_selection_table_size
    ) ecmp_selector_sel;

    table nexthop_resolve {
        key = {
            ig_md.nhop_idx : exact;
            ig_md.hash : selector;
        }
        actions = {
            drop; ipv4_forward; ipv4_forward_direct_connect;
        }
        size = ecmp_table_size;
        const default_action = drop;
        implementation = ecmp_selector_sel;
    }

    table populate_lkp {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.udp.isValid() : exact;
            hdr.tcp.isValid() : exact;
            hdr.ndp_s_data.isValid() : ternary;
        }
        actions = {
            set_lkp_tcp; set_lkp_udp; set_lkp_ip_unknown; drop; NoAction;
            set_lkp_ndp;
        }
    }

    action invalidate_update_and_send(MulticastGroupId_t grp) {
        set_high_priority();
        ig_intr_tm_md.bypass_egress = 0;
        hdr.update_meta.setInvalid();
        ig_intr_tm_md.mcast_grp_a = grp;
        ig_intr_tm_md.level1_mcast_hash = 1;
        ig_intr_tm_md.level2_mcast_hash = 1;
        hdr.trim_meta.setValid();
        hdr.trim_meta.pkt_type = PKT_TYPE_NOTIFY;
        hdr.trim_meta.egress_port = ig_intr_tm_md.ucast_egress_port;
    }

    table act_on_update {
        key = {
            ig_intr_tm_md.ucast_egress_port : exact;
        }
        actions = {
            invalidate_update_and_send; drop;
        }
        // say 2 is our mcast clone session
        default_action = invalidate_update_and_send(0x1000);
    }

    apply {
        configure_ndp.apply();
        // always deflect on drop by tm
        ig_intr_tm_md.bypass_egress = 1;

        // for the moment only accept ipv4 packets
        if (!hdr.ipv4.isValid()) {
            drop();
        } else {
            populate_lkp.apply();
            compute_ip_hash(ig_md.lkp, ig_md.hash);
            // IP forwarding and friends
            ipv4_lpm.apply();
            nexthop_resolve.apply();
            arp.apply();
            if (hdr.trim_meta.isValid() && hdr.trim_meta.pkt_type == PKT_TYPE_NOTIFY) {
                nr_arm.count(hdr.trim_meta.egress_port);
                // command pipe to become pessimistic starting now (transition e1)
                arm0.execute(hdr.trim_meta.egress_port);
                arm1.execute(hdr.trim_meta.egress_port);
                drop();
            } else if (hdr.update_meta.isValid()) {
                act_on_update.apply();
                return_chop.count(ig_intr_tm_md.ucast_egress_port);
            } else {
                // start ndp logic
                bit<1> r1 = transition_0.execute(ig_intr_tm_md.ucast_egress_port);
                bit<1> r2 = transition_1.execute(ig_intr_tm_md.ucast_egress_port);
                pkt_color_t pesicolor = (bit<2>)meter_pessimistic.execute(ig_intr_tm_md.ucast_egress_port);
                pkt_color_t halfcolor = (bit<2>)meter_halftimistic.execute(ig_intr_tm_md.ucast_egress_port);
                pkt_color_t opticolor = (bit<2>)meter_optimistic.execute(ig_intr_tm_md.ucast_egress_port);
                if (allow_pessimism == 1w0) {
                    nr_opti.count(ig_intr_tm_md.ucast_egress_port);
                    qos_md.color = opticolor;
                } else {
                    if (r1 == 1w1) {
                        nr_pesi.count(ig_intr_tm_md.ucast_egress_port);
                        qos_md.color = pesicolor;
                    } else if (r2 == 1w1) {
                        nr_half.count(ig_intr_tm_md.ucast_egress_port);
                        qos_md.color = halfcolor;
                    } else {
                        nr_opti.count(ig_intr_tm_md.ucast_egress_port);
                        qos_md.color = opticolor;
                    }
                }

                if (!ig_md.drop_ndp && hdr.udp.isValid() &&
                     (hdr.ndp_s_ctrl.isValid() || hdr.ndp_s_data.isValid())) {
                     per_port_counter.count(ig_intr_tm_md.ucast_egress_port);
                    // NDP special case
                    // INVARIANT: IsTruncated(p) ==> IsNDPData(p)
                    if (hdr.ndp_s_ctrl.isValid()) {
                        // If this is a control packet (ACK/NACK), which is
                        // indicated by the ndp.flags field, then we want
                        // to directly send these packets to the high
                        // priority queue.
                        set_high_priority();
                    } else if (!ig_md.always_truncate && qos_md.color == SWITCH_METER_COLOR_GREEN) {
                        // For non-control packets, check the meter.
                        // If its green, then go to the low-priority queue
                        // otherwise, mirror packet
                        set_low_priority();
                    } else {
                        meter_chop.count(ig_intr_tm_md.ucast_egress_port);
                        truncate.apply();
                    }
                } else {
                    per_port_counter.count(ig_intr_tm_md.ucast_egress_port);
                    // any other kind of traffic gets mapped to QID == 2
                    // in order not to interfere with ndp
                    // anything other than NDP simply passes through
                    ig_intr_tm_md.qid = 2;
                }
            }
        }
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) reach_egress;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) dod_chop;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) ig_chopped;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) trim_metas;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) mcast_received;
    Counter<bit<32>, PortId_t>(32w4096, CounterType_t.PACKETS) mcast_received_actual;
    action drop() {
        eg_intr_dprs_md.drop_ctl = 1;
    }
    action nop() {}
    action set_ndp_data_flags() {
        hdr.ndp_s_data.flags = hdr.ndp_s_data.flags | (8w1 << 7);
        // TODO: is it right? 46 == 64 - 14 (sizeof(ethernet)) - 4 (sizeof(ether_trailer))
        // TODO: please make it configurable
        hdr.ipv4.total_len = 46;
        hdr.udp.hdr_lenght = 26;
    }
    action do_invalidate_trim() {
        hdr.trim_meta.setInvalid();
    }
    action invalidate_trim() {
        hdr.trim_meta.setInvalid();
        set_ndp_data_flags();
    }
    action invalidate_trim_and_set_update(bit<8> also_add) {
        hdr.trim_meta.setInvalid();
        hdr.ipv4.total_len = 46;
        hdr.udp.hdr_lenght = 26;
        hdr.ndp_s_data.flags = also_add;
        hdr.update_meta.setValid();
        hdr.update_meta.pkt_type = PKT_TYPE_MIRROR_UPDATE;
    }
    table act_on_egress {
        key = {
            eg_intr_md.egress_port : exact;
        }
        actions = {
            nop; drop;
            invalidate_trim; invalidate_trim_and_set_update;
        }
        default_action = invalidate_trim();
    }
    table act_on_notification {
        key = {
            eg_intr_md.egress_port : exact;
        }
        actions = {
            nop; do_invalidate_trim;
        }
        const default_action = do_invalidate_trim();
        const entries = {
            (0 << 7 | 68) : nop();
            (1 << 7 | 68) : nop();
            (2 << 7 | 68) : nop();
            (3 << 7 | 68) : nop();
        }
    }
    action set_eg_mirror(MirrorId_t session_id) {
        eg_md.mirror_session_id = session_id;
    }

    table eg_port2_egmirror {
        key = {
            hdr.normal_meta.egress_port : exact;
        }
        actions = {
            drop; set_eg_mirror;
        }
        default_action = drop();
    }
    apply {
        reach_egress.count(eg_intr_md.egress_port);
        // INVARIANT: hdr.ndp_s_data.isValid() == true
        if (hdr.egmeta.isValid()) {
            ig_chopped.count(eg_intr_md.egress_port);
            // this is a chop ordered by ingress => rewrite and send out
            hdr.ethernet.src_addr = hdr.egmeta.srcAddr;
            hdr.ethernet.dst_addr = hdr.egmeta.dstAddr;
            hdr.egmeta.setInvalid();
            set_ndp_data_flags();
        } else {
            if (hdr.trim_meta.isValid()) {
                if (hdr.trim_meta.pkt_type == PKT_TYPE_TRIM) {
                    // step 6.X where X is the current pipe_id =>
                    // we are in DoDx port => send it out as it will
                    // be forwarded back to ingress (step 7.X)
                    trim_metas.count(hdr.trim_meta.egress_port);
                    act_on_egress.apply();
                } else {
                    mcast_received.count(eg_intr_md.egress_port);
                    act_on_notification.apply();
                }
                // else if pkt_type == PKT_TYPE_NOTIFY => do nothing and let packet back into ingress
            } else {
                // normal ndp_data packet from ingress
                if (eg_intr_md.deflection_flag == 1w1) {
                    // step 1: got DoD
                    dod_chop.count(hdr.normal_meta.egress_port);
                    eg_port2_egmirror.apply();
                    hdr.trim_meta.setValid();
                    hdr.trim_meta.pkt_type = PKT_TYPE_TRIM;
                    hdr.trim_meta.egress_port = hdr.normal_meta.egress_port;
                    eg_intr_dprs_md.mirror_type = 3w1;
                    hdr.normal_meta.setInvalid();
                    drop();
                    // step 2: forward packet with trim_meta which will arrive back in ingress (step 3)
                    // step 4: clone packet. It will get replicated to all DoD ports in all pipelines (step 5.*)
                } else {
                    hdr.normal_meta.setInvalid();
                }
            }
        }
    }
}
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
