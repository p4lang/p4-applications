control Table0_control(inout headers hdr,
                       inout metadata local_meta,
                       inout standard_metadata_t standard_metadata) {

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }
    
    action set_egress_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action _drop() {
        mark_to_drop();
    }
    
    table table0 {
        key = {
            standard_metadata.ingress_port : ternary;
            hdr.ethernet.srcAddr          : ternary;
            hdr.ethernet.dstAddr          : ternary;
            hdr.ethernet.etherType        : ternary;
            hdr.ipv4.srcAddr              : ternary;
            hdr.ipv4.dstAddr              : ternary;
            hdr.ipv4.protocol              : ternary;
        }
        actions = {
            set_egress_port();
            send_to_cpu();
            _drop();
        }
        const default_action = _drop();
    }

    apply {
        table0.apply();
     }
}
