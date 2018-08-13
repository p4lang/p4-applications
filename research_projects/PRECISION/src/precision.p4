/* -*- P4_16 -*- */
/*
  Reference Implementation of the PRECISION heavy-hitter detection algorithm. Please skip to the egress pipeline.

  Released under Apache 2.0 license. You may obtain a copy of Apache 2.0 at https://www.apache.org/licenses/LICENSE-2.0
*/

#define FLOW_TABLE_SIZE_EACH 1024
#define HASH_BASE 10w0
#define HASH_MAX 10w1023




#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

// Headers and Metadata definitions

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct custom_metadata_t {
	bit<64> my_flowID;
	bit<64> my_estimated_count;
	bit<1> already_matched;

	bit<64> carry_min;
	bit<64> carry_min_plus_one;
	bit<8> min_stage;
	bit<1> do_recirculate;
	bit<9> orig_egr_port;

	bit<32> hashed_address_s1;
	bit<32> hashed_address_s2;
	bit<32> hashed_address_s3;

	bit<64> random_bits;
	bit<12> random_bits_short;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

// Standard IPv4 parser, dummy ingress processing

parser MyParser(packet_in packet,
                out headers hdr,
                inout custom_metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout custom_metadata_t meta) {
    apply {  }
}


control MyIngress(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
	// We did some rudimentary forwarding in the ingress pipeline, only for demo purpose.
    action repeater () {
		// Under basic mininet setup in P4 tutorial, we have one switch and two hosts, at port 1/2.
		// We repeat packets from h1 to h2 and vice virsa.
        standard_metadata.egress_spec = 9w3 - standard_metadata.ingress_port;
    }
	action bouncer () {
		// We reflect all packets to its sender.
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
		if(hdr.ipv4.isValid()){
			// Choose from repeater or bouncer, or add your real IPv4 forwarding?
			repeater();
		}else{
			mark_to_drop();
		}
	}
}

// =========== Start implementation of PRECISION ============
// A brief introduction to Precision algorithm:
// 1. We maintain many (flow ID, packet count) tuples
// 2. When new packet comes and a tuple already exist for this flow, we increment the counter.
//    Otherwise, we simulate Space-Saving/RAP algorithm, find the approximate minimum counter and evict.
// 3. We use recirculation to evict entry and evict with probability 1/(min+1).
// In this example, we implement d=3 version of PRECISON, which maintain 3 pairs of flow tables.

control MyEgress(inout headers hdr,
                 inout custom_metadata_t meta,
				 inout standard_metadata_t standard_metadata) {
	register<bit<64> >(FLOW_TABLE_SIZE_EACH)  flow_table_ids_1;
	register<bit<64> >(FLOW_TABLE_SIZE_EACH)  flow_table_ctrs_1;
	register<bit<64> >(FLOW_TABLE_SIZE_EACH)  flow_table_ids_2;
	register<bit<64> >(FLOW_TABLE_SIZE_EACH)  flow_table_ctrs_2;
	register<bit<64> >(FLOW_TABLE_SIZE_EACH)  flow_table_ids_3;
	register<bit<64> >(FLOW_TABLE_SIZE_EACH)  flow_table_ctrs_3;

	action commpute_flow_id () {
		meta.my_flowID[31:0]=hdr.ipv4.srcAddr;
		meta.my_flowID[63:32]=hdr.ipv4.dstAddr;
	}

	action compute_reg_index () {
		// Each flow ID is hashed into d=3 different locations
		hash(meta.hashed_address_s1, HashAlgorithm.crc16, HASH_BASE,
			 	{hdr.ipv4.srcAddr, 7w11, hdr.ipv4.dstAddr}, HASH_MAX);

		hash(meta.hashed_address_s2, HashAlgorithm.crc16, HASH_BASE,
			 	{3w5, hdr.ipv4.srcAddr, 5w3, hdr.ipv4.dstAddr}, HASH_MAX);

		hash(meta.hashed_address_s3, HashAlgorithm.crc16, HASH_BASE,
			 	{2w0, hdr.ipv4.dstAddr, 1w1, hdr.ipv4.srcAddr}, HASH_MAX);
	}


	action clone_and_recirc_replace_entry(){
		// We need to set up a mirror ID in order to make this work.
		// Use simple_switch_CLI: mirroring_add 0 0
		#define MIRROR_ID 0
		clone3<custom_metadata_t>(CloneType.E2E, MIRROR_ID, meta);
		// Recirculated packets carried meta.min_stage and meta.count_min, so they themselves know what to do.
	}

	table naive_approximation {
		// Goal: recirculate using probability 1/2^x nearest to 1/(carry_min+1), x between [1..63]
		actions = {
            NoAction();
			clone_and_recirc_replace_entry();
        }
        key = {
            meta.carry_min: ternary;
			meta.random_bits: ternary;
        }
        size = 128;
		default_action = NoAction();
		const entries = {
#include "entries_naive.p4"
		}
	}

	table better_approximation {
		// Goal: recirculate using probability 1/(2^x*T) nearest to 1/(carry_min+1), x between [1..63], T between [8..15]
		actions = {
            NoAction();
			clone_and_recirc_replace_entry();
        }
        key = {
            meta.carry_min_plus_one: ternary;
			meta.random_bits: ternary;
			meta.random_bits_short: range;
        }
        size = 128;
		default_action = NoAction();
		const entries = {
#include "entries_better.p4"
		}
	}

	apply {
		commpute_flow_id();
		compute_reg_index();

		bit<64> tmp_existing_flow_id;
		bit<64> tmp_existing_flow_count;

		meta.my_estimated_count=0;

		if(standard_metadata.instance_type==0){
			// Regular incoming packets.
			// We check if the flow ID is already in the flow table.
			// If not, we remember the minimum counter we've seen so far.

			// access table 1
			flow_table_ids_1.read(tmp_existing_flow_id, meta.hashed_address_s1);
			flow_table_ctrs_1.read(tmp_existing_flow_count, meta.hashed_address_s1);
			if(tmp_existing_flow_count==0 || tmp_existing_flow_id==meta.my_flowID){
				flow_table_ids_1.write(meta.hashed_address_s1, meta.my_flowID);
				flow_table_ctrs_1.write(meta.hashed_address_s1, tmp_existing_flow_count+1);

				meta.my_estimated_count=tmp_existing_flow_count+1;
				meta.already_matched=1;

			}else{
				//save min_stage
				//special case for first stage: always min
				meta.carry_min=tmp_existing_flow_count;
				meta.min_stage=1;
			}

			// access table 2
			if(meta.already_matched==0){
				flow_table_ids_2.read(tmp_existing_flow_id, meta.hashed_address_s2);
				flow_table_ctrs_2.read(tmp_existing_flow_count, meta.hashed_address_s2);
				if(tmp_existing_flow_count==0 || tmp_existing_flow_id==meta.my_flowID){
					flow_table_ids_2.write(meta.hashed_address_s2, meta.my_flowID);
					flow_table_ctrs_2.write(meta.hashed_address_s2, tmp_existing_flow_count+1);

					meta.my_estimated_count=tmp_existing_flow_count+1;
					meta.already_matched=1;

				}else{
					//save min_stage
					if(meta.carry_min>tmp_existing_flow_count){
						meta.carry_min=tmp_existing_flow_count;
						meta.min_stage=2;
					}
				}
			}

			// access table 3
			if(meta.already_matched==0){
				flow_table_ids_3.read(tmp_existing_flow_id, meta.hashed_address_s3);
				flow_table_ctrs_3.read(tmp_existing_flow_count, meta.hashed_address_s3);
				if(tmp_existing_flow_count==0 || tmp_existing_flow_id==meta.my_flowID){
					flow_table_ids_3.write(meta.hashed_address_s3, meta.my_flowID);
					flow_table_ctrs_3.write(meta.hashed_address_s3, tmp_existing_flow_count+1);

					meta.my_estimated_count=tmp_existing_flow_count+1;
					meta.already_matched=1;

				}else{
					//save min_stage
					if(meta.carry_min>tmp_existing_flow_count){
						meta.carry_min=tmp_existing_flow_count;
						meta.min_stage=3;
					}
				}
			}

			// decide to recirculate or not...
			if(meta.already_matched==0){
				// Ideally, we need to recirculate with probability 1/(carry_min+1).
				// There are three options for probabilistic recircuation.
				// 1. Perfect probability: use precisely 1/(carry_min+1) probabilty. May not be supported by all hardware.
				// 2. Better (9/8)-approximation: use a 4-bit floating point to approximate carry_min. Require range match.
				// 3. Naive 2-approximation: approximate 1/(carry_min+1) to the nearest power of 2. Require only ternary match.
				// See paper for more detail.

				//#define PERFECT_PROBABILITY
				#define BETTER_APPROXIMATE
				#if defined(PERFECT_PROBABILITY)
				{
					bit<64> rnd;
					random<bit<64> >(rnd,64w0,meta.carry_min);
					if(rnd==0){
						clone_and_recirc_replace_entry();
					}

				}
				#elif defined(BETTER_APPROXIMATE)
				{
					random<bit<64> >(meta.random_bits,64w0,64w0-1);
					random<bit<12> >(meta.random_bits_short,12w0,12w0-1);
					meta.carry_min_plus_one=meta.carry_min+1;
					better_approximation.apply();

				}
				#else
				{
					random<bit<64> >(meta.random_bits,64w0,64w0-1);
					naive_approximation.apply();
				}
				#endif
			}



		}else{
			// This packet is a recirculated packet.
			// Since we use Clone and Recirculate / Clone and Resubmit, we always drop them.
			mark_to_drop();

			// We replace the flow ID in the flow tables, and increment the counter.
			if(meta.min_stage==1){
				flow_table_ids_1.write(meta.hashed_address_s1, meta.my_flowID);
				flow_table_ctrs_1.write(meta.hashed_address_s1, meta.carry_min+1);
			}
			if(meta.min_stage==2){
				flow_table_ids_2.write(meta.hashed_address_s2, meta.my_flowID);
				flow_table_ctrs_2.write(meta.hashed_address_s2, meta.carry_min+1);
			}
			if(meta.min_stage==3){
				flow_table_ids_3.write(meta.hashed_address_s3, meta.my_flowID);
				flow_table_ctrs_3.write(meta.hashed_address_s3, meta.carry_min+1);
			}

		}


		// Write result to packet header for demo purpose.
		// In actual applications, we can use the estimated count for decision making in data plane.
		hdr.ethernet.dstAddr = 0xffffffffffff;
		hdr.ethernet.srcAddr = meta.my_estimated_count[47:0];
	}
}

// =========== End implementation of PRECISION ===========

// We did not change header, no need to recompute checksum
control MyComputeChecksum(inout headers hdr, inout custom_metadata_t meta) {
     apply { }
}


// Minimal deparser etc.
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

