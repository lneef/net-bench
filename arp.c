#include "arp.h"
#include "packet.h"
#include "util.h"

static int check_arp(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr =
      rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  return eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
}

static int wait_for_arp(struct port_info *info, struct rte_mbuf **mbuf) {
  for (;;) {
    uint16_t rx_nb = rte_eth_rx_burst(info->port_id, info->rx_queue, mbuf, 1);
    if (rx_nb == 1 && check_arp(*mbuf))
      return 0;
    rte_pause();
  }
}

int process_arp(struct rte_mbuf *mbuf, struct port_info *info) {
  struct rte_ether_hdr *eth_hdr =
      rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
  switch (rte_be_to_cpu_16(arp_hdr->arp_opcode)) {
  case RTE_ARP_OP_REQUEST: {
    if (arp_hdr->arp_data.arp_tip != info->pkt_config.ipv4.src_ip) {
      rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "ARP request for other IP\n");
      return -1;
    }
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&info->pkt_config.eth.src_mac, &eth_hdr->src_addr);
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
    rte_ether_addr_copy(&info->pkt_config.eth.src_mac,
                        &arp_hdr->arp_data.arp_sha);
    SWAP(arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip,
         typeof(arp_hdr->arp_data.arp_tip));
    return 0;
  }
  case RTE_ARP_OP_REPLY: {
    if (arp_hdr->arp_data.arp_tip != info->pkt_config.ipv4.src_ip)
      return -1;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "ARP from resolved\n");
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
                        &info->pkt_config.eth.dst_mac);
    rte_pktmbuf_free(mbuf);
    return 0;
  }
  default:
    return -1;
  }
}

int resolve_arp(struct port_info *info) {
  struct rte_mbuf *arp_pkt;
  do {
    arp_pkt = rte_pktmbuf_alloc(info->ctrl_pool);
    if (!arp_pkt) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
              "Failed to allocate ARP packet\n");
      return -1;
    }
    packet_arp_ctor(arp_pkt, info);
    uint16_t tx_nb =
        rte_eth_tx_burst(info->port_id, info->tx_queue, &arp_pkt, 1);
    if (tx_nb < 1)
      continue;
    wait_for_arp(info, &arp_pkt);
  } while (process_arp(arp_pkt, info) < 0);
  return 0;
}
