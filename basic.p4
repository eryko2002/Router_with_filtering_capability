/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
// const bit<16> TYPE_VLAN = 0x8100;
const bit<8>  TYPE_TCP = 6; 
const bit<8>  TYPE_ICMP = 0x01;
const bit<8>  TYPE_UDP = 0x11;
const bit<16> TYPE_ARP = 0x0806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
// typedef bit<12> vid_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// header vlan_t {
// 		bit<3>		pcp;
// 		bit<1>		cfi;
// 		bit<12>		vid;
// 		bit<16>		etherType;
// }

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

header arp_t {
    bit<16> hrd; // Hardware Type
    bit<16> pro; // Protocol Type
    bit<8> hln; // Hardware Address Length
    bit<8> pln; // Protocol Address Length
    bit<16> op;  // Opcode
    macAddr_t sha; // Sender Hardware Address
    ip4Addr_t spa; // Sender Protocol Address
    macAddr_t tha; // Target Hardware Address
    ip4Addr_t tpa; // Target Protocol Address
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    arp_t		     arp;
		// vlan_t			 vlan;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
						// TYPE_VLAN: parse_vlan;
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    // state parse_vlan {
    //     packet.extract(hdr.vlan);
    //     transition select(hdr.ethernet.etherType) {
    //         TYPE_IPV4: parse_ipv4;
    //         default: accept;
    //     }
    //     //transition parse_ipv4;
    // }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_arp {
		  packet.extract(hdr.arp);
		  transition accept;
	  }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
		verify_checksum(true, {
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
        },
        hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
	}
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(512, CounterType.packets) RxCounter;
    counter(1, CounterType.packets) DropCounter;

    action drop() {
        DropCounter.count(0);
        mark_to_drop(standard_metadata);
    }

    action arp_process (ip4Addr_t target_ip, macAddr_t target_mac) {
      hdr.arp.op = 2;

      hdr.arp.tha = hdr.arp.sha;
      hdr.arp.tpa = hdr.arp.spa;

      hdr.arp.sha = target_mac;
      hdr.arp.spa = target_ip;


      hdr.ethernet.srcAddr = target_mac;
      hdr.ethernet.dstAddr = hdr.arp.tha;

      standard_metadata.egress_spec =  standard_metadata.ingress_port;
    }

    table arp_table {
		    key = {
		    	hdr.arp.tpa: exact;
		    }
		    actions = {
		    	arp_process;
          drop;
		    	NoAction;
		    }
		    size = 1024;
		    default_action = drop();
	  }

     action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // Routing
        standard_metadata.egress_spec = port;
        // 2 layer
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
     }

    // action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    // action add_tag(macAddr_t dstAddr, egressSpec_t port, vid_t vid) {
    //     // Routing
    //     standard_metadata.egress_spec = port;

    //     // 2 layer
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;

    //     // ttl dec
    //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

		// 		// Add VLAN tag
		// 		hdr.vlan.setValid();
    //     hdr.vlan.vid = vid;
    //     hdr.vlan.pcp = 1;
    //     hdr.vlan.cfi = 0;
    //     hdr.vlan.etherType = hdr.ethernet.etherType;
    //     hdr.ethernet.etherType = TYPE_VLAN;
    // }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            // add_tag;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    table firewall {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.protocol: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // action forward_tag(macAddr_t dstAddr, egressSpec_t port) {
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    //     standard_metadata.egress_spec = port;
    //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    // }

    // action remove_tag(macAddr_t dstAddr, egressSpec_t port) {
		// 		hdr.vlan.setInvalid();
    //     hdr.ethernet.etherType = TYPE_IPV4;
    //     standard_metadata.egress_spec = port;
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    // }

    // table vlan_exact {
    //     key = {
    //         hdr.vlan.vid: exact;
    //     }
    //     actions = {
    //         forward_tag;
    //         remove_tag;
    //         drop;
    //         NoAction;
    //     }
    //     size = 1024;
    //     default_action = drop();
    // }

    apply { 
        // if (hdr.vlan.isValid()) {
        //     vlan_exact.apply();
        // }

        // if (hdr.ipv4.isValid() && !hdr.vlan.isValid()) {
        //     ipv4_lpm.apply();
        // }
        bit<32> ingress_port_32;
        ingress_port_32 = (bit<32>) standard_metadata.ingress_port;
        RxCounter.count(ingress_port_32);
        
        if (standard_metadata.checksum_error == 1){
            drop();
            return;
        }

        if (hdr.arp.isValid()) {
            arp_table.apply();
        }
        else if (hdr.ipv4.isValid() && hdr.ipv4.protocol != TYPE_ICMP) {
            if (hdr.ipv4.ttl < 2){
                drop();
                // DropCounter.count(0);
                return;
            }
            else if (firewall.apply().miss) {
              ipv4_lpm.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    counter(512, CounterType.packets) TxCounter;
    counter(512, CounterType.packets) ForwardCounter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply { 
        if (standard_metadata.egress_port != 0){
            bit<32> ingress_port_32;
            bit<32> egress_port_32;
            ingress_port_32 = (bit<32>) standard_metadata.ingress_port;
            egress_port_32 = (bit<32>) standard_metadata.egress_port;
            ForwardCounter.count(ingress_port_32);
            TxCounter.count(egress_port_32);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        // packet.emit(hdr.vlan);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
