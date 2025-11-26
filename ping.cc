#include <bits/time.h>
#include <cstdint>
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
#include <span>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <vector>

#include "packet.h"
#include "port.h"
#include "statistics.h"
#include "util.h"

static uint16_t handle_pong_rdtsc(port_info *info, std::span<rte_mbuf *> pkts,
                                  uint16_t nb_rx) {
  pkt_content_rdtsc pc, rc;
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
  rte_pktmbuf_free_bulk(pkts.data(), nb_rx);
  return rx_count;
}

static void add_timestamp_rtdsc(port_info *info, std::span<rte_mbuf *> pkts) {
  pkt_content_rdtsc pc{rte_get_timer_cycles()};
  for (uint16_t i = 0; i < info->config.burst_size; ++i) {
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

static void print_stats(port_info *pinfo) {
  auto &stats = pinfo->statistics;
  auto &sub_stats = pinfo->submit_statistics;
  auto rtime = pinfo->config.rtime;
  double avg_latency_us =
      (double)stats->time / (rte_get_timer_hz() / 1e6) / stats->received;
  double min_latency_us = (double)stats->min / (rte_get_timer_hz() / 1e6);
  printf("-----Statistics-----\n");
  printf("Reached PPS: %.2f\n", (double)(stats->received) / rtime);
  printf("Average latency: %.2f us -- Min latency: %.2f\n", avg_latency_us,
         min_latency_us);
  printf("Submitted PPS: %.2f\n", (double)(sub_stats->subitted) / rtime);
  printf("Packets with incorrect checksum: %lu \n", stats->cksum_incorrect);
}

static int lcore_ping(void *port) {
  port_info *pinfo = (port_info *)port;
  pinfo->statistics->min = UINT64_MAX;
  auto &config = pinfo->config;
  std::vector<rte_mbuf *> pkts(config.burst_size);
  std::vector<rte_mbuf *> rpkts(config.burst_size);
  uint16_t tx_nb = config.burst_size;
  uint64_t wait_cycles = time_between_bursts(config.bps);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
  uint64_t deadline;
  rte_mempool_obj_iter(pinfo->send_pool.get(), packet_mempool_ctor, pinfo);
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    if (rte_mempool_get_bulk(pinfo->send_pool.get(), (void **)pkts.data(),
                             tx_nb)) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
              "Failed to allocated burst of size %u\n", tx_nb);
      continue;
    }
    add_timestamp_rtdsc(pinfo, pkts);
    tx_nb = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts.data(),
                             config.burst_size);
    pinfo->submit_statistics->subitted += tx_nb;
    deadline = cycles + wait_cycles;
    uint16_t rx_nb = 0, rx_total = 0;
    // wait until time slice expires (bps) or sent packets are received
    do {
      rx_nb = rte_eth_rx_burst(pinfo->port_id, pinfo->rx_queue, rpkts.data(),
                               config.burst_size);
      if (rx_nb)
        rx_total += handle_pong_rdtsc(pinfo, rpkts, rx_nb);

    } while (rx_total < tx_nb && rte_get_timer_cycles() < deadline);
  }
  return 0;
}


static int lcore_send(void* port){
    port_info *pinfo = static_cast<port_info*>(port);
    auto& config = pinfo->config;
    std::vector<rte_mbuf*> pkts(config.burst_size);
    uint16_t tx_nb = config.burst_size, tx_left = 0;
    uint64_t cycles = rte_get_timer_cycles();
    uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
    rte_mempool_obj_iter(pinfo->send_pool.get(), packet_mempool_ctor_cksum, pinfo);
    for(; cycles < end; cycles = rte_get_timer_cycles()){
        if(rte_mempool_get_bulk(pinfo->send_pool.get(), (void**)pkts.data(), tx_nb))
            tx_left = 0;
        tx_nb = rte_eth_tx_burst(pinfo->port_id, pinfo->tx_queue, pkts.data() + tx_left, config.burst_size - tx_left);
        tx_left = config.burst_size - tx_left - tx_nb;
        pinfo->submit_statistics->subitted += tx_nb;
    }
    return 0;
}

int main(int argc, char *argv[]) {
  int dpdk_argc = rte_eal_init(argc, argv);
  if (dpdk_argc < 0)
    return -1;
  port_info pinfo(role::PING, argc - dpdk_argc, argv + dpdk_argc);
  if(pinfo.configure())
      return -1;
  switch (pinfo.config.opmode) {
      case mode::SEND:
          lcore_send(&pinfo);
          break;
        case mode::SDRV:
          lcore_ping(&pinfo);
          break;
        default:
          break;
  }
  print_stats(&pinfo);
  return 0;
}
