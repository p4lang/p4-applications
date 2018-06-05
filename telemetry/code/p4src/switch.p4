#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"
#include "checksum.p4"
#include "table0.p4"
#include "int.p4"

control IngressImpl(inout headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    Table0_control() table0_control;
    Int_ingress() int_ingress;
    
    apply{
        /* ... ingress code here ... */
        int_ingress.apply(hdr, meta, standard_metadata);
        table0_control.apply(hdr, meta, standard_metadata);
        /* ... ingress code here ... */
    }
}

control EgressImpl(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata)
{
    Int_egress() int_egress;

    apply{
        /* ... egress code here ... */
        int_egress.apply(hdr, meta, standard_metadata);
        /* ... egress code here ... */
    }
}

V1Switch(ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()) main;