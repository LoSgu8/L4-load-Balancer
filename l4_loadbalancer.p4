/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PORT_WIDTH 9

#define CLIENT_PORT_IDX 1

#define BACKEND1_IDX 2
#define BACKEND2_IDX 3
#define BACKEND3_IDX 4
#define BACKEND4_IDX 5

#define NB_BACKEND 4
#define NB_TCP_PORTS 65536

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* Ethernet header */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/* IPv4 header */
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* TCP header */
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

    // TCP options are seen as pkt data (not parsed)
}

/* Metadata structure is used to pass information
 * across the actions, or the control block.
 * It is also used to pass information from the 
 * parser to the control blocks.
 */
struct metadata {
    bit<16> l4_payload_length;
    /* Used to understand if the packet belongs to a configured VIP */
    bit<1> pkt_is_virtual_ip;
    /* Used to keep track of the current backend assigned to a connection */
    bit<9> assigned_backend;
    /* TODO: Add here other metadata */
}

struct headers {
    /* TODO 4: Define here the headers structure */
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
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
        /* Parsing Ethernet Header */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        /* This information is used to recalculate the checksum 
         * in the MyComputeChecksum control block.
         * Since we modify the TCP header, we need to recompute the checksum.
         * We do it for you, so don't worry about it.
         */
        meta.l4_payload_length = hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) << 2);

        /* Transition to the parse_tcp state */
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        /* Parsing TCP header */
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    /* Definition of the register where you keep information about
     * the backend assigned to a connection.
     */

    // Register to find the backend number associated to a connection given the TCP port client side (3 bits are enough for 8 backend)
    register<bit<3>>(NB_TCP_PORTS) backend_reg;

    /* Definition of the register where you keep information about
     * the number of connections assigned to a backend
     */
    // Register that stores the counter (32 bits) of the number of conenctions assigned at each backend
    register<bit<32>>(NB_BACKEND) nb_connections_reg;

    /* Drop action */
    action drop() {
        mark_to_drop(standard_metadata);
        return;
    }

    /* Forward action */
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* This action is executed after a lookup on the vip_to_backend table */
    action update_backend_info(bit<32> ip, bit<16> port, bit<48> dstMac) {
        /* Updating the packet fields before redirecting the 
         * packet to the backend.
         */

        // ETH: src becomes dst addr and dst addr is the MAC of the backend assigned
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        // IP: update the dst addr with the IP of the backend assigned
        hdr.ipv4.dstAddr = ip;
        // TCP: src port remains the same and dst port is the port of the backend assigned (8000)
        hdr.tcp.dstPort = port;

        // Update the egress port with the backend assigned
        standard_metadata.egress_spec = meta.assigned_backend;
    }

    /* Define here all the other actions that you might need */

    /* This action is executed to check if the current packet is 
     * destined to a virtual IP configured on the load balancer.
     * This action is complete, you don't need to change it.
     */
    action is_virtual_ip(bit<1> val) {
        meta.pkt_is_virtual_ip = val;
    }

    /* This action is executed for packets coming from the backend servers.
     * You need to update the packet fields before redirecting the packet
     * to the client.
     * This action is executed after a lookup on the backend_to_vip table.
     */
    action backend_to_vip_conversion(bit<32> srcIP, bit<16> port, bit<48> srcMac) {
        /* Update the packet fields before redirecting the 
         * packet to the client.
         */

        // ETH: update the src addr with the MAC of the load balancer and the dst addr with the MAC of the client
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = 0x0a000001;

        // IP: update the src addr with the IP of the load balancer
        hdr.ipv4.srcAddr = srcIP;

        //TCP: update the src port with the port used by the client to connect to the load balancer
        hdr.tcp.srcPort = port;

        // Update the egress port with the client port
        standard_metadata.egress_spec = CLIENT_PORT_IDX;
        
    }

    /* Table used map a backend index with its information */
    table vip_to_backend {
        key = {
            meta.assigned_backend : exact;
        }
        actions = {
            update_backend_info;
            drop;
        }
        default_action = drop();
    }

    /* Table used to understand if the current packet is destined 
     * to a configured virtual IP 
     */
    table virtual_ip {
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.tcp.dstPort : exact;
        }
        actions = {
            is_virtual_ip;
            drop;
        }
        default_action = drop();
    }

    /* Table used to map a backend with the information about the VIP */
    table backend_to_vip {
        key = {
            hdr.ipv4.srcAddr : lpm;
        }
        actions = {
            backend_to_vip_conversion;
            drop;
        }
        default_action = drop();
    }

    apply {
        
        if (hdr.tcp.isValid()) {
            /* Check if the ingress port is the one connected to the client. */
            if (standard_metadata.ingress_port == CLIENT_PORT_IDX) {
                
                
                /* Verify whether the packet is destined for the Virtual IP 
                * If not, drop the packet.
                * If yes, continue with the ingress logic
                */
                virtual_ip.apply();

                if (meta.pkt_is_virtual_ip != 1) {
                    /* Packet not destined to a virtual IP */
                    drop();

                } else {
                    /* Packet destined to a virtual IP */

                    /* Check if the current connection is already assigned to a specific 
                    * backend server. 
                    * If yes, forward the packet to the assigned backend (but first check the FIN or RST flag).
                    * If not, assign a new backend to the connection (only is the packet has the SYN flag set)
                    * otherwise, drop the packet.
                    */

                    bit<3> backend_nb; // variable that stores the backend number associated to the current connection (retrieved from backend_reg)
                    bit<32> nb_connections; // variable that temporarily stores the number of connections of a backend (retrieved from nb_connections_reg)
                    
                    backend_reg.read(backend_nb, (bit<32>)hdr.tcp.srcPort);

                    if (backend_nb < 2 || backend_nb > 5) {
                        /* Connection not assigned to a backend */
                        if (hdr.tcp.syn == 1) { 
                            /* New connection with SYN flag */

                            /* Define the logic to assign a new backend to the connection.
                             * You should assign the backend with the minimum number of connections.
                             * If there are multiple backends with the same number of connections,
                             * you should assign the backend with the lowest index.
                             */

                            bit<32> min_nb; // variable that stores the minimum number of connections of a backend

                            nb_connections_reg.read(min_nb, 0);
                            meta.assigned_backend = 2;

                            nb_connections_reg.read(nb_connections, 3);
                            if (nb_connections < min_nb) {
                                min_nb = nb_connections;
                                meta.assigned_backend = 5;
                            }

                            nb_connections_reg.read(nb_connections, 2);
                            if (nb_connections < min_nb) {
                                min_nb = nb_connections;
                                meta.assigned_backend = 4;
                            }

                            nb_connections_reg.read(nb_connections, 1);
                            if (nb_connections < min_nb) {
                                min_nb = nb_connections;
                                meta.assigned_backend = 3;
                            }

                            /* Assign the backend to the connection and increment the number of connections */
                            backend_reg.write((bit<32>)hdr.tcp.srcPort, (bit<3>)meta.assigned_backend);
                            nb_connections_reg.write((bit<32>)(meta.assigned_backend-2), min_nb + 1);

                            vip_to_backend.apply();

                        } else { 
                            /* Connection not allocated and SYN flag not set */
                            drop();
                        }
                    } else {
                        /* Connection already assigned to a backend */
                        /* If the packet is already assigned, and if the FIN or RST flags are enabled 
                         * you should remove the assignment and decrement the number of connections
                         * for the backend. Finally, forward the packet to the backend.
                         */

                        /* FIN or RST flags are enabled */
                        if (hdr.tcp.fin == 1 || hdr.tcp.rst == 1) {

                            nb_connections_reg.read(nb_connections, (bit<32>)(backend_nb-2));

                            /* Remove the assignment and decrement the number of connections */
                            backend_reg.write((bit<32>)hdr.tcp.srcPort, 0);
                            nb_connections_reg.write((bit<32>)(backend_nb-2), nb_connections - 1);
                            
                        }

                        /* Before redirecting the packet from CLIENT to BACKEND, make sure
                         * to update the packet fields (IP, MAC, etc.).
                         */

                        /* Forward the packet to the backend */
                        meta.assigned_backend = (bit<9>)backend_nb;
                        vip_to_backend.apply();

                    }

                }

            } else {
                /* Packet coming from the backend */
                /* If the packet is coming from the other direction, make sure
                * to update the packet fields (IP, MAC, etc.) before redirecting it
                * to the client. The backend_to_vip table is used to get the information
                * about the VIP.
                */

                backend_to_vip.apply();

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
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
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
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        // Note: the following does not support TCP options.
        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.ipv4.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4_payload_length,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.cwr,
                hdr.tcp.ece,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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