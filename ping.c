#include <bits/time.h>
#include <generic/rte_cycles.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
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
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "packet.h"
#include "port.h"
#include "statistics.h"
#include "util.h"

static uint16_t handle_pong_rdtsc(struct port_info *info,
                                  struct rte_mbuf **pkts, uint16_t nb_rx) {
  struct pkt_content_rdtsc pc, rc;
  uint64_t elapsed = 0;
  uint16_t rx_count = 0;
  pc.time = rte_get_timer_cycles();
  for (uint16_t i = 0; i < nb_rx; ++i) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkts[i], uint8_t *, HDR_SIZE);
    if (packet_verify_ipv4(pkts[i]) || packet_verify_rs(info, pkts[i]))
      continue;
    ++rx_count;
    if (packet_verify_cksum(info, pkts[i])) {
      ++info->statistics->cksum_incorrect;
      continue;
    }
    PUN(&rc, data, typeof(rc));
    elapsed = pc.time - rc.time;
    info->statistics->time += elapsed;
    info->statistics->min = RTE_MIN(info->statistics->min, elapsed);
    ++info->statistics->received;
  }
  rte_pktmbuf_free_bulk(pkts, nb_rx);
  return rx_count;
}

static void add_timestamp_rtdsc(struct port_info *info,
                                struct rte_mbuf **pkts) {
  struct pkt_content_rdtsc pc = {.time = rte_get_timer_cycles()};
  for (uint16_t i = 0; i < info->burst_size; ++i) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkts[i], uint8_t *, HDR_SIZE);
    PUN(data, &pc, typeof(pc));
    packet_ipv4_udp_cksum(pkts[i], info);
  }
}

static uint64_t time_between_bursts(uint64_t bps) {
  uint64_t interval = rte_get_timer_hz() / bps;
  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "Time between bursts: %lu cycles\n",
          interval);
  return interval;
}

static void print_submit_stat(struct port_info *pinfo) {
  struct submit_stat *sub_stats = pinfo->submit_statistics;
  printf("Submitted PPS: %.2f\n",
         (double)(sub_stats->submitted) / pinfo->rtime);
}

static void print_stats(struct port_info *pinfo) {
  struct stat *stats = pinfo->statistics;
  double avg_latency_us =
      (double)stats->time / (rte_get_timer_hz() / 1e6) / stats->received;
  double min_latency_us = (double)stats->min / (rte_get_timer_hz() / 1e6);
  printf("-----Statistics-----\n");
  printf("Reached PPS: %.2f\n", (double)(stats->received) / pinfo->rtime);
  printf("Average latency: %.2f us -- Min latency: %.2f\n", avg_latency_us,
         min_latency_us);
  print_submit_stat(pinfo);
  printf("Packets with incorrect checksum: %lu \n", stats->cksum_incorrect);
}

int lcore_ping(void *port) {
  struct port_info *pinfo = (struct port_info *)port;
  pinfo->statistics->min = UINT64_MAX;
  struct rte_mbuf **pkts =
      rte_calloc(NULL, pinfo->burst_size, sizeof(struct rte_mbuf *),
                 RTE_CACHE_LINE_MIN_SIZE);
  struct rte_mbuf **rpkts =
      rte_calloc(NULL, pinfo->burst_size, sizeof(struct rte_mbuf *),
                 RTE_CACHE_LINE_MIN_SIZE);

  uint16_t tx_nb = pinfo->burst_size;
  uint64_t wait_cycles = time_between_bursts(pinfo->bps);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = pinfo->rtime * rte_get_timer_hz() + cycles;
  uint64_t deadline;
  rte_mempool_obj_iter(pinfo->send_pool, packet_mempool_ctor, pinfo);
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    if (rte_mempool_get_bulk(pinfo->send_pool, (void **)pkts, tx_nb)) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
              "Failed to allocated burst of size %u\n", tx_nb);
      continue;
    }
    add_timestamp_rtdsc(pinfo, pkts);
    tx_nb = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts,
                             pinfo->burst_size);
    pinfo->submit_statistics->submitted += tx_nb;
    deadline = cycles + wait_cycles;
    uint16_t rx_nb = 0, rx_total = 0;
    do {
      rx_nb = rte_eth_rx_burst(pinfo->port_id, pinfo->rx_queue, rpkts,
                               pinfo->burst_size);
      if (rx_nb)
        rx_total += handle_pong_rdtsc(pinfo, rpkts, rx_nb);

    } while (rx_total < tx_nb && rte_get_timer_cycles() < deadline);
  }
  return 0;
}

int lcore_send(void *port) {
  struct port_info *pinfo = (struct port_info *)port;
  struct rte_mbuf **pkts =
      rte_calloc(NULL, pinfo->burst_size, sizeof(struct rte_mbuf *),
                 RTE_CACHE_LINE_MIN_SIZE);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = pinfo->rtime * rte_get_timer_hz() + cycles;
  uint16_t tx_free = pinfo->burst_size, tx_nb;
  rte_mempool_obj_iter(pinfo->send_pool, packet_mempool_ctor_full, pinfo);
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    if (!rte_mempool_get_bulk(pinfo->send_pool, (void **)pkts, tx_free)) 
      tx_free = 0;
    
    tx_nb = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts + tx_free,
                             pinfo->burst_size - tx_free);
    tx_free += tx_nb;
    pinfo->submit_statistics->submitted += tx_nb;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  struct port_info *pinfo;
  int dpdk_argc = rte_eal_init(argc, argv);
  if (dpdk_argc < 0)
    return -1;
  if (port_info_ctor(&pinfo, PING, argc - dpdk_argc, argv + dpdk_argc) < 0)
    return -1;
  switch (pinfo->pimode) {
  case SEND:
    lcore_send(pinfo);
    print_submit_stat(pinfo);
    break;
  case SDRV:
    lcore_ping(pinfo);
    print_stats(pinfo);
    break;
  }

  port_info_dtor(pinfo);
  return 0;
}
