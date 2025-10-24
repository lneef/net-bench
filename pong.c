#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <signal.h>

#include "arp.h"
#include "port.h"
#include "util.h"
#include "packet.h"

static int terminate = 0;

static void handler(int sig) {
    (void)sig;
    terminate = 1;
}


static int packet_pong_ctor(struct port_info *pinfo, struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth + 1);
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  if (packet_verify_cksum(pkt)) {
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "invalid udp checksum\n");
    return -1;
  }
  udp->dgram_cksum = 0;
  ipv4->hdr_checksum = 0;
  ipv4->time_to_live = TTL;
  SWAP(udp->src_port, udp->dst_port, typeof(udp->src_port));
  SWAP(ipv4->src_addr, ipv4->dst_addr, typeof(ipv4->src_addr));
  packet_ipv4_cksum(pkt, pinfo);;
  rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
  rte_ether_addr_copy(&pinfo->pkt_config.eth.src_mac, &eth->src_addr);
  return 0;
}

static int handle_packet(struct port_info *info, struct rte_mbuf *pkt,
                         packet_ipv4 ipv4_handler) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  switch (rte_be_to_cpu_16(eth->ether_type)) {
  case RTE_ETHER_TYPE_ARP:
    return process_arp(pkt, info);
  case RTE_ETHER_TYPE_IPV4:
    return ipv4_handler(info, pkt);
  default:
    rte_pktmbuf_free(pkt);
  }
  return -1;
}

static int lcore_pong(void *port) {
  int ret;
  struct port_info *info = (struct port_info *)port;
  struct rte_mbuf *pkts[BURST_SIZE];
  struct rte_mbuf *pkts_out[BURST_SIZE];
  uint16_t nb_rx, nb_tx = 0, nb_rm = 0;
  for (;!terminate;) {
    nb_rx =
        rte_eth_rx_burst(info->port_id, info->rx_queue, pkts + nb_rm, info->burst_size - nb_rm);
    int j = 0, i = nb_rm + nb_rx - 1;
    for (; i >= 0; --i, ++j) {
      pkts_out[j] = pkts[i];
      ret = handle_packet(info, pkts_out[j], packet_pong_ctor);
      if (unlikely(ret < 0))
        --j;
    }
    nb_tx = rte_eth_tx_burst(info->port_id, info->tx_queue, pkts_out, j);
    nb_rm = j - nb_tx;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  struct port_info *pinfo;
  struct sigaction sa = {0};
  sa.sa_handler = handler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  int dpdk_argc = rte_eal_init(argc, argv);
  if (dpdk_argc < 0)
    return -1;
  if (port_info_ctor(&pinfo, ROLE_PONG, argc - dpdk_argc, argv + dpdk_argc))
    return -1;
  lcore_pong(pinfo);
  port_info_dtor(pinfo);

  rte_eal_cleanup();
  return 0;
}
