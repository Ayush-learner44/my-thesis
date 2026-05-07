#include <core.p4>
#include <v1model.p4>

// ================================================================
// CONSTANTS
// ================================================================

const bit<16> ETHERTYPE_IPV6 = 0x86DD;
const bit<8>  PROTO_TCP      = 6;
const bit<9>  TCP_SYN        = 9w0x002;
const bit<9>  TCP_ACK        = 9w0x010;

// Ports on merge_sw facing each downstream switch.
// These must match the port1= values in network.py addLink calls.
// h1-h5 are on ports 1-5; path_a_sw on port 6; path_b_sw on port 7.
const bit<9>  PATH_A_PORT    = 6;   // pure SYN traffic → detector switch
const bit<9>  PATH_B_PORT    = 7;   // ACK / other traffic → passthrough switch

// ================================================================
// HEADERS
// ================================================================

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv6_t     ipv6;
    tcp_t      tcp;
}

struct metadata_t { }

// ================================================================
// PARSER
// ================================================================

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV6: parse_ipv6;
            default:        accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            PROTO_TCP: parse_tcp;
            default:   accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

// ================================================================
// VERIFY CHECKSUM
// ================================================================

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ================================================================
// INGRESS
// ================================================================

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Controller installs MAC → port mappings for all hosts and switches.
    // Used for return traffic (server → clients) going through this switch.
    table l2_forward {
        key     = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; drop; NoAction; }
        size    = 64;
        default_action = NoAction();
    }

    apply {

        if (standard_metadata.ingress_port == PATH_A_PORT ||
            standard_metadata.ingress_port == PATH_B_PORT) {

            // ── Return path ───────────────────────────────────────────
            // Traffic arriving FROM path_a_sw or path_b_sw is server→client
            // return traffic (SYN-ACK, data, FIN).  Just L2-forward it to
            // the correct host — no flag-based splitting.
            l2_forward.apply();

        } else {

            // ── Host → server path ────────────────────────────────────
            // Traffic arriving from any host port (1-5).
            // Split by TCP flags: pure SYN goes to detector, everything
            // else (SYN-ACK, ACK, FIN, data) goes to the passthrough switch.

            if (hdr.tcp.isValid() &&
                (hdr.tcp.flags & TCP_SYN) != 0 &&
                (hdr.tcp.flags & TCP_ACK) == 0) {

                // Pure SYN → path_a_sw (detector with CMS)
                standard_metadata.egress_spec = PATH_A_PORT;

            } else {

                // Everything else → path_b_sw (simple passthrough)
                standard_metadata.egress_spec = PATH_B_PORT;

            }
        }
    }
}

// ================================================================
// EGRESS
// ================================================================

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// ================================================================
// COMPUTE CHECKSUM
// ================================================================

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ================================================================
// DEPARSER
// ================================================================

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
    }
}

// ================================================================
// SWITCH INSTANTIATION
// ================================================================

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
