#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_udp.h>
#include <stdint.h>

#include "packet.h"
#include "port.h"

int packet_eth_ctor(struct rte_mbuf *mbuf, struct rte_ether_hdr *eth,
                    struct eth_config *config, rte_be16_t ether_type) {
  rte_ether_addr_copy(&config->src_mac, &eth->src_addr);
  rte_ether_addr_copy(&config->dst_mac, &eth->dst_addr);
  eth->ether_type = ether_type;
  mbuf->l2_len = sizeof(struct rte_ether_hdr);
  mbuf->data_len += sizeof(struct rte_ether_hdr);
  mbuf->pkt_len += sizeof(struct rte_ether_hdr);
  return 0;
}

int packet_udp_ctor(struct rte_mbuf *mbuf, struct rte_udp_hdr *udp,
                    struct udp_config *config, uint16_t dgram_len) {
  udp->src_port = rte_cpu_to_be_16(config->src_port);
  udp->dst_port = rte_cpu_to_be_16(config->dst_port);
  udp->dgram_len = rte_cpu_to_be_16(dgram_len);
  udp->dgram_cksum = 0;
  mbuf->l4_len = sizeof(struct rte_udp_hdr);
  mbuf->data_len += dgram_len;
  mbuf->pkt_len += dgram_len;
  return 0;
}

int packet_ipv4_ctor(struct rte_mbuf *mbuf, struct rte_ipv4_hdr *ipv4,
                     struct ipv4_config *config, uint16_t total_length) {
  ipv4->src_addr = config->src_ip;
  ipv4->dst_addr = config->dst_ip;
  ipv4->version_ihl = RTE_IPV4_VHL_DEF;
  ipv4->time_to_live = TTL;
  ipv4->next_proto_id = IPPROTO_UDP;
  ipv4->total_length = rte_cpu_to_be_16(total_length);
  ipv4->packet_id = 0;
  ipv4->fragment_offset = 0;
  ipv4->type_of_service = 0;
  ipv4->hdr_checksum = 0;
  mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
  mbuf->data_len += sizeof(struct rte_ipv4_hdr);
  mbuf->pkt_len += sizeof(struct rte_ipv4_hdr);
  return 0;
}

int packet_pp_ctor_udp(struct rte_mbuf *mbuf, struct packet_config *config) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth + 1);
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  mbuf->data_len = 0;
  mbuf->pkt_len = 0;
  uint32_t payload = config->frame_size - HDR_SIZE;
  packet_udp_ctor(mbuf, udp, &config->udp,
                  payload += sizeof(struct rte_udp_hdr));
  packet_ipv4_ctor(mbuf, ipv4, &config->ipv4,
                   payload += sizeof(struct rte_ipv4_hdr));
  packet_eth_ctor(mbuf, eth, &config->eth,
                  rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4));
  mbuf->nb_segs = 1;
  return 0;
}

void packet_arp_ctor(struct rte_mbuf *mbuf, struct port_info *info) {
  struct rte_ether_hdr *eth_hdr =
      rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
  mbuf->pkt_len = 0;
  mbuf->data_len = 0;
  packet_eth_ctor(mbuf, eth_hdr, &info->pkt_config.eth,
                  rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP));

  arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
  arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
  arp_hdr->arp_plen = sizeof(uint32_t);
  arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
  rte_ether_addr_copy(&info->pkt_config.eth.src_mac,
                      &arp_hdr->arp_data.arp_sha);
  arp_hdr->arp_data.arp_sip = info->pkt_config.ipv4.src_ip;
  arp_hdr->arp_data.arp_tip = info->pkt_config.ipv4.dst_ip;
  mbuf->pkt_len += sizeof(struct rte_arp_hdr);
  mbuf->data_len += sizeof(struct rte_arp_hdr);
}

void packet_ipv4_cksum(struct rte_mbuf *mbuf, struct port_info *info) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  if (!info->pkt_config.ipv4.chcksum_offload)
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
  else
    mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
}

void packet_udp_cksum(struct rte_mbuf *mbuf, struct port_info *info) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  if (!info->pkt_config.udp.chcksum_offload) {
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, udp);
  } else {
    mbuf->ol_flags |=
        RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
    udp->dgram_cksum = rte_ipv4_phdr_cksum(ipv4, mbuf->ol_flags);
  }
}

void packet_ipv4_udp_cksum(struct rte_mbuf *mbuf, struct port_info *info) {
  packet_udp_cksum(mbuf, info);
  packet_ipv4_cksum(mbuf, info);
}

int packet_verify_cksum(struct rte_mbuf *mbuf) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  int ipv4_cksum = rte_ipv4_cksum(ipv4);
  ipv4->hdr_checksum = 0;
  int udp_cksum = rte_ipv4_udptcp_cksum_verify(ipv4, udp);
  return ipv4_cksum || (udp->dgram_cksum != 0 && udp_cksum);
}

int packet_verify_ipv4(struct rte_mbuf *mbuf){
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    return !(rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4);
}

void packet_mempool_ctor(struct rte_mempool *mp, void *opaque, void *obj, unsigned int obj_idx __rte_unused){
    struct rte_mbuf *mbuf = (struct rte_mbuf *)obj;
    struct port_info *info = (struct port_info *)opaque;
    packet_pp_ctor_udp(mbuf, &info->pkt_config);

    mbuf->port = info->port_id;
    mbuf->pool = mp;
    mbuf->next = NULL;
}
