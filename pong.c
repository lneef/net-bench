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

#include "port.h"
#include "packet.h"
#include "statistics.h"

static int terminate = 0;

static void handler(int sig) {
    (void)sig;
    terminate = 1;
}

static int packet_mempool_alloc(struct rte_mempool *mp, struct rte_mbuf **pkts, uint16_t nb){
    return rte_mempool_get_bulk(mp, (void**)pkts, nb);
}

static void packet_copy_payload(struct port_info* info, struct rte_mbuf *src, struct rte_mbuf *dst) {
    uint8_t* data = rte_pktmbuf_mtod_offset(src, uint8_t*, HDR_SIZE);
    uint8_t* dst_data = rte_pktmbuf_mtod_offset(dst, uint8_t*, HDR_SIZE);
    rte_memcpy(dst_data, data, sizeof(struct pkt_content_rdtsc));
    packet_ipv4_udp_cksum(dst, info);
}

static int handle_packet(struct port_info* info, struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  switch (rte_be_to_cpu_16(eth->ether_type)) {
  case RTE_ETHER_TYPE_IPV4:
    return packet_verify_cksum(info, pkt);
  default:
    break;
  }
  return -1;
}

static int lcore_pong(void *port) {
  struct port_info *info = (struct port_info *)port;
  struct rte_mbuf *pkts[BURST_SIZE];
  struct rte_mbuf *pkts_out[BURST_SIZE];
  uint16_t nb_rx, nb_tx = 0;
  rte_mempool_obj_iter(info->send_pool, packet_mempool_ctor, info);
  for (;!terminate;) {
    nb_rx =
        rte_eth_rx_burst(info->port_id, info->rx_queue, pkts, info->burst_size);
    if(nb_rx == 0)
        continue;
    if(likely(packet_mempool_alloc(info->send_pool, pkts_out, nb_rx))){
        // drop packets
        rte_pktmbuf_free_bulk(pkts, nb_rx);
        continue;
    }
    int j = 0;
    for (int i = 0; i < nb_rx; ++i) {
        if(unlikely(handle_packet(info, pkts[i])))
            continue;
        packet_copy_payload(info, pkts[i], pkts_out[j++]);
    }
    rte_pktmbuf_free_bulk(pkts, nb_rx);
    nb_tx = rte_eth_tx_burst(info->port_id, info->tx_queue, pkts_out, j);
    rte_pktmbuf_free_bulk(pkts_out + nb_tx, j - nb_tx);

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
  if (port_info_ctor(&pinfo, PONG, argc - dpdk_argc, argv + dpdk_argc))
    return -1;
  lcore_pong(pinfo);
  port_info_dtor(pinfo);

  rte_eal_cleanup();
  return 0;
}
