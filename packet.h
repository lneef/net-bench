#ifndef PACKET_H
#define PACKET_H

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include "port.h"

#define TTL 64

int packet_eth_ctor(struct rte_mbuf* mbuf, struct rte_ether_hdr *eth,
                           struct eth_config *config, rte_be16_t ether_type); 

int packet_udp_ctor(struct rte_mbuf* mbuf, struct rte_udp_hdr *udp,
                           struct udp_config *config, uint16_t dgram_len);

int packet_ipv4_ctor(struct rte_mbuf* mbuf, struct rte_ipv4_hdr *ipv4,
                            struct ipv4_config *config, uint16_t total_length);

int packet_pp_ctor_udp(struct rte_mbuf *mbuf,
                              struct packet_config *config, uint16_t payload_size);

void packet_arp_ctor(struct rte_mbuf *mbuf, struct port_info *info);

void packet_ipv4_cksum(struct rte_mbuf *mbuf, struct port_info *info);

void packet_udp_cksum(struct rte_mbuf *mbuf, struct port_info *info);

void packet_ipv4_udp_cksum(struct rte_mbuf *mbuf, struct port_info *info);

int packet_verify_cksum(struct rte_mbuf *mbuf);
#endif
