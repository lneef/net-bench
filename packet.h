#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include "port.h"

static constexpr uint8_t TTL = 64;
static constexpr uint16_t HDR_SIZE = (sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr));

void packet_eth_ctor(rte_mbuf* mbuf, rte_ether_hdr *eth,
                           eth_config *config, rte_be16_t ether_type); 

void packet_udp_ctor(rte_mbuf* mbuf, rte_udp_hdr *udp,
                           udp_config *config, uint16_t dgram_len);

void packet_ipv4_ctor(rte_mbuf* mbuf, rte_ipv4_hdr *ipv4,
                            ipv4_config *config, uint16_t total_length);

void packet_pp_ctor_udp(rte_mbuf *mbuf,
                              packet_config *config);

void packet_arp_ctor(rte_mbuf *mbuf, port_info *info);

void packet_ipv4_cksum(rte_mbuf *mbuf, port_info *info);

void packet_ipv4_udp_cksum(rte_mbuf *mbuf, port_info *info);

int packet_verify_cksum(port_info* info,rte_mbuf *mbuf);

int packet_verify_rs(port_info* info, rte_mbuf *mbuf);

int packet_verify_ipv4(rte_mbuf *mbuf);

void packet_mempool_ctor(rte_mempool *mp, void *opaque, void *obj, unsigned obj_idx __rte_unused);

void packet_mempool_ctor_cksum(rte_mempool *mp, void *opaque, void *obj, unsigned obj_idx __rte_unused);

#endif
