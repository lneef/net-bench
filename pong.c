#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>

#include <arpa/inet.h>
#include <rte_mempool.h>
#include <signal.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "packet.h"
#include "port.h"
#include "util.h"

static int terminate = 0;
static int timestamp_offset = -1;
static const struct rte_mbuf_dynfield timestamp_desc = {
    .name = "dynfield_timestamp",
    .size = sizeof(rte_mbuf_timestamp_t),
    .align = alignof(rte_mbuf_timestamp_t),
};
static struct {
  rte_mbuf_timestamp_t total;
  uint64_t total_pkts;
} stats;

static void handler(int sig) {
  (void)sig;
  terminate = 1;
}

static rte_mbuf_timestamp_t *get_timestamp_field(struct rte_mbuf *mbuf) {
  return RTE_MBUF_DYNFIELD(mbuf, timestamp_offset, rte_mbuf_timestamp_t *);
}
static uint16_t add_timestamps(uint16_t port __rte_unused,
                               uint16_t qidx __rte_unused,
                               struct rte_mbuf **pkts, uint16_t nb_pkts,
                               uint16_t max_pkts __rte_unused,
                               void *_ __rte_unused) {
  rte_mbuf_timestamp_t timestamp = rte_get_timer_cycles();
  for (uint16_t i = 0; i < nb_pkts; ++i) {
    rte_mbuf_timestamp_t *ts = get_timestamp_field(pkts[i]);
    *ts = timestamp;
  }
  return nb_pkts;
}

static uint16_t appl_time(uint16_t port __rte_unused,
                          uint16_t qidx __rte_unused, struct rte_mbuf **pkts,
                          uint16_t nb_pkts, void *_ __rte_unused) {
  rte_mbuf_timestamp_t curr_time = rte_get_timer_cycles();
  for (uint16_t i = 0; i < nb_pkts; ++i) {
    rte_mbuf_timestamp_t *ts = get_timestamp_field(pkts[i]);
    stats.total += curr_time - *ts;
  }
  stats.total_pkts += nb_pkts;
  return nb_pkts;
}

static int packet_pong_ctor(struct port_info *pinfo, struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth + 1);
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  if (packet_verify_cksum(pinfo, pkt)) {
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "invalid udp checksum\n");
    return -1;
  }
  udp->dgram_cksum = 0;
  ipv4->hdr_checksum = 0;
  ipv4->time_to_live = TTL;
  SWAP(udp->src_port, udp->dst_port, typeof(udp->src_port));
  SWAP(ipv4->src_addr, ipv4->dst_addr, typeof(ipv4->src_addr));
  packet_ipv4_udp_cksum(pkt, pinfo);
  rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
  rte_ether_addr_copy(&pinfo->pkt_config.eth.src_mac, &eth->src_addr);
  return 0;
}

static int handle_packet(struct port_info *info, struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  switch (rte_be_to_cpu_16(eth->ether_type)) {
  case RTE_ETHER_TYPE_IPV4:
    return packet_pong_ctor(info, pkt);
  default:
    rte_pktmbuf_free(pkt);
  }
  return -1;
}

static int lcore_pong(void *port) {
  int ret;
  struct port_info *pinfo = (struct port_info *)port;
  struct rte_mbuf **pkts =
      rte_calloc("", pinfo->burst_size, sizeof(struct rte_mbuf *),
                 RTE_CACHE_LINE_MIN_SIZE);
  struct rte_mbuf **pkts_out =
      rte_calloc("", pinfo->burst_size, sizeof(struct rte_mbuf *),
                 RTE_CACHE_LINE_MIN_SIZE);
  uint16_t nb_rx, nb_tx = 0, nb_rm = 0;
  rte_eth_add_rx_callback(pinfo->port_id, pinfo->rx_queue, add_timestamps,
                          NULL);
  rte_eth_add_tx_callback(pinfo->port_id, pinfo->tx_queue, appl_time, NULL);
  for (; !terminate;) {
    nb_rx = rte_eth_rx_burst(pinfo->port_id, pinfo->rx_queue, pkts,
                             pinfo->burst_size - nb_rm);
    for (uint16_t i = 0; i < nb_rx; ++i) {
      pkts_out[nb_rm] = pkts[i];
      ret = handle_packet(pinfo, pkts_out[nb_rm]);
      if (likely(!ret))
        ++nb_rm;
    }
    nb_tx = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts_out, nb_rm);
    for (uint16_t i = nb_tx, j = 0; i < nb_rm; ++i, ++j)
      pkts_out[j] = pkts_out[i];
    ;
    nb_rm = nb_rm - nb_tx;
  }
  rte_free(pkts);
  rte_free(pkts_out);
  printf("Average time in application: %.2f\n",
         (double)stats.total / (rte_get_timer_hz() / 1e6) / stats.total_pkts);

  return 0;
}

static int lcore_recv(void *port) {
  struct port_info *pinfo = (struct port_info *)port;
  struct rte_mbuf **pkts =
      rte_calloc("", pinfo->burst_size, sizeof(struct rte_mbuf *),
                 RTE_CACHE_LINE_MIN_SIZE);

  uint16_t nb_rx;
  uint64_t rcvd = 0;
  for (; !terminate;) {
    nb_rx = rte_eth_rx_burst(pinfo->port_id, pinfo->rx_queue, pkts,
                             pinfo->burst_size);
    rcvd += nb_rx;
    rte_pktmbuf_free_bulk(pkts, nb_rx);
  }
  rte_free(pkts);
  printf("Packets received: %lu\n", rcvd);
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
  timestamp_offset = rte_mbuf_dynfield_register(&timestamp_desc);
  if (timestamp_offset < 0) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
            "Failed to register timestamp dynfield\n");
    goto cleanup;
  }
  switch (pinfo->pomode) {
  case RECV:
    lcore_recv(pinfo);
    break;
  case RVSD:
    lcore_pong(pinfo);
    break;
  }
  port_info_dtor(pinfo);
cleanup:
  rte_eal_cleanup();
  return 0;
}
