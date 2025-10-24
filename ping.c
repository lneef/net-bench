#include <bits/time.h>
#include <generic/rte_cycles.h>
#include <netinet/in.h>
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
#include <rte_udp.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "arp.h"
#include "packet.h"
#include "port.h"
#include "statistics.h"
#include "util.h"

struct pkt_content {
  struct timespec time;
} __rte_packed;

static uint64_t sub(struct timespec *end, struct timespec *start) {
  uint64_t sec, nsec;
  if (end->tv_nsec < start->tv_nsec) {
    sec = end->tv_sec - start->tv_sec - 1;
    nsec = 1e9 + end->tv_nsec - start->tv_sec;
  } else {
    sec = end->tv_sec - start->tv_sec;
    nsec = end->tv_nsec - start->tv_nsec;
  }
  return sec * 1e9 + nsec;
}

static void handle_pong(struct port_info *info, struct rte_mbuf **pkts,
                        uint16_t nb_rx) {
  alignas(struct timespec) struct pkt_content pc, rc;
  uint64_t burst_time;
  clock_gettime(CLOCK_MONOTONIC, &pc.time);
  for (uint16_t i = 0; i < nb_rx; ++i) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkts[i], uint8_t *,
                                            sizeof(struct rte_ether_hdr) +
                                                sizeof(struct rte_ipv4_hdr) +
                                                sizeof(struct rte_udp_hdr));
    if (packet_verify_cksum(pkts[i])) {
      ++info->statistics->cksum_incorrect;
      continue;
    }
    PUN(&rc, data, typeof(rc));
    burst_time = sub(&pc.time, &rc.time);
    ++info->statistics->received;
  }
  rte_pktmbuf_free_bulk(pkts, nb_rx);
  info->statistics->time += (double)burst_time / 1e3;
}

static void add_timestamp(struct port_info *info, struct rte_mbuf **pkts) {
  alignas(struct timespec) struct pkt_content pc;
  clock_gettime(CLOCK_MONOTONIC, &pc.time);
  for (uint16_t i = 0; i < info->burst_size; ++i) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkts[i], uint8_t *,
                                            sizeof(struct rte_ether_hdr) +
                                                sizeof(struct rte_ipv4_hdr) +
                                                sizeof(struct rte_udp_hdr));
    PUN(data, &pc, typeof(pc));
    packet_ipv4_udp_cksum(pkts[i], info);
  }
}

static uint64_t time_between_bursts(uint64_t pps, uint16_t burst_size) {
  uint64_t interval = (rte_get_timer_hz() * burst_size) / pps;
  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "Time between bursts: %lu cycles\n",
          interval);
  return interval;
}

static void print_stats(struct port_info *pinfo) {
  struct stat *stats = pinfo->statistics;
  struct submit_stat *sub_stats = pinfo->submit_statistics;
  printf("Reached PPS: %.2f\n", (double)(stats->received) / pinfo->rtime);
  printf("Average latency: %.2f us\n", (double)(stats->time) / stats->received);
  printf("Submitted PPS: %.2f\n", (double)(sub_stats->subitted) / pinfo->rtime);
}

int lcore_receiver(void *port) {
  struct port_info *pinfo = (struct port_info *)port;
  struct rte_mbuf *rpkts[BURST_SIZE];
  pinfo->statistics =
      rte_calloc(NULL, 1, sizeof(struct stat), RTE_CACHE_LINE_MIN_SIZE);
  if (!pinfo->statistics) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "No memory\n");
    return -ENOMEM;
  }
  uint16_t rx_nb;
  uint64_t end = pinfo->rtime * rte_get_timer_hz() + rte_get_timer_cycles();
  for (; rte_get_timer_cycles() < end;) {
    rx_nb = rte_eth_rx_burst(pinfo->port_id, pinfo->rx_queue, rpkts,
                             pinfo->burst_size);
    if (rx_nb)
      handle_pong(pinfo, rpkts, rx_nb);
  }
  return 0;
}

int lcore_sender(void *port) {
  struct port_info *pinfo = (struct port_info *)port;
  pinfo->submit_statistics =
      rte_calloc(NULL, 1, sizeof(struct submit_stat), RTE_CACHE_LINE_MIN_SIZE);
  if (!pinfo->submit_statistics) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "No memory\n");
    return -ENOMEM;
  }
  struct rte_mbuf *pkts[BURST_SIZE];
  uint16_t tx_nb = pinfo->burst_size;
  uint64_t wait_cycles = time_between_bursts(pinfo->pps, pinfo->burst_size);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = pinfo->rtime * rte_get_timer_hz() + cycles;
  for (; rte_get_timer_cycles() < end;) {
    if (rte_pktmbuf_alloc_bulk(pinfo->mbuf_pool, pkts, tx_nb)) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
              "Failed to allocated burst of size %u\n", tx_nb);
    }
    for (int i = 0; i < tx_nb; ++i) {
      packet_pp_ctor_udp(pkts[i], &pinfo->pkt_config,
                         sizeof(struct pkt_content));
    }
    add_timestamp(pinfo, pkts);
    tx_nb = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts,
                             pinfo->burst_size);
    pinfo->submit_statistics->subitted += tx_nb;
    cycles += wait_cycles;
    // Busy wait: bit wasteful but reduces jitter
    while (rte_get_timer_cycles() < cycles)
      rte_pause();
  }
  return 0;
}

int lcore_sender_single(void *port) {
  struct port_info *pinfo = (struct port_info *)port;
  pinfo->submit_statistics =
      rte_calloc(NULL, 1, sizeof(struct submit_stat), RTE_CACHE_LINE_MIN_SIZE);
  if (!pinfo->submit_statistics) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "No memory\n");
    return -ENOMEM;
  }
  struct rte_mbuf *rpkts[BURST_SIZE];
  pinfo->statistics =
      rte_calloc(NULL, 1, sizeof(struct stat), RTE_CACHE_LINE_MIN_SIZE);
  if (!pinfo->statistics) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "No memory\n");
    return -ENOMEM;
  }
  uint16_t rx_nb;

  struct rte_mbuf *pkts[BURST_SIZE];
  uint16_t tx_nb = pinfo->burst_size;
  uint64_t wait_cycles = time_between_bursts(pinfo->pps, pinfo->burst_size);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = pinfo->rtime * rte_get_timer_hz() + cycles;
  for (; cycles < end;) {
    if (rte_pktmbuf_alloc_bulk(pinfo->mbuf_pool, pkts, tx_nb)) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
              "Failed to allocated burst of size %u\n", tx_nb);
    }
    for (int i = 0; i < tx_nb; ++i) {
      packet_pp_ctor_udp(pkts[i], &pinfo->pkt_config,
                         sizeof(struct pkt_content));
    }
    add_timestamp(pinfo, pkts);
    tx_nb = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts,
                             pinfo->burst_size);
    pinfo->submit_statistics->subitted += tx_nb;
    cycles += wait_cycles;
    // Busy wait: bit wasteful but reduces jitter
    do {
      rx_nb = rte_eth_rx_burst(pinfo->port_id, pinfo->rx_queue, rpkts,
                               pinfo->burst_size);
      if (rx_nb)
        handle_pong(pinfo, rpkts, rx_nb);

    } while (rte_get_timer_cycles() < cycles);
  }
  return 0;
}

int main(int argc, char *argv[]) {
  struct port_info *pinfo;
  int dpdk_argc = rte_eal_init(argc, argv);
  int ret;
  if (dpdk_argc < 0)
    return -1;
  if (port_info_ctor(&pinfo, ROLE_PING, argc - dpdk_argc, argv + dpdk_argc) < 0)
    return -1;
  if (resolve_arp(pinfo) < 0) {
    ret = -1;
    goto cleanup;
  }
  if (pinfo->no_threading) {
    lcore_sender_single(pinfo);
  } else {
    int (*lcore_fun[])(void *) = {lcore_sender, lcore_receiver};
    if (launch_lcores(lcore_fun, pinfo, 2) < 0) {
      ret = -1;
      goto cleanup;
    }
  }
  print_stats(pinfo);
  ret = 0;
cleanup:
  port_info_dtor(pinfo);
  return ret;
}
