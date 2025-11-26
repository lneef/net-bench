#pragma once
#include <cstdint>
#include <memory>
#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <memory.h>

#include "statistics.h"

#define BURST_SIZE 32
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define MEMPOOL_CACHE_SIZE 256
#define NUM_MBUFS 8191
#define NUM_SENDBUF (2 * TX_RING_SIZE - 1)

#define ETHER_SIZE (RTE_ETHER_MAX_LEN + RTE_PKTMBUF_HEADROOM)
#define JUMBO_SIZE (RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM)

enum class role { PING, PONG };
enum class mode {SEND, SDRV, RECV, RVSD};

struct eth_config {
  rte_ether_addr src_mac;
  rte_ether_addr dst_mac;
};

struct ipv4_config {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t packet_id;
  bool chcksum_offload;
  bool rx_chcksum_offload;
};

struct udp_config {
  uint16_t src_port;
  uint16_t dst_port;
  bool chcksum_offload;
  bool rx_chcksum_offload;
};

struct packet_config {
  eth_config eth;
  ipv4_config ipv4;
  udp_config udp;
  uint32_t frame_size;
};

using mempool_ptr =
    std::unique_ptr<rte_mempool, decltype(std::addressof(rte_mempool_free))>;

struct port_config {
  uint16_t burst_size;
  uint64_t bps;
  uint64_t rtime;
  mode opmode;
  packet_config pkt_config;
};

struct port_info;

void port_init_cmdline(port_info *info, int argc, char **argv);

struct port_info {
  uint16_t port_id;
  uint16_t rx_queue;
  uint16_t tx_queue;
  port_config config;
  mempool_ptr mbuf_pool, send_pool;
  stat* statistics;
  submit_stat* submit_statistics;
  port_info(role rl, int argc, char **argv)
      : mbuf_pool(rte_pktmbuf_pool_create(
                      "MBUF_POOL", NUM_MBUFS, MEMPOOL_CACHE_SIZE, 0,
                      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()),
                  &rte_mempool_free),
        send_pool(nullptr, nullptr), statistics(static_cast<stat*>(rte_calloc("stat", 1, sizeof(stat), RTE_CACHE_LINE_SIZE))),
        submit_statistics(static_cast<submit_stat*>(rte_calloc("submit_stat", 1, sizeof(submit_stat), RTE_CACHE_LINE_SIZE))) {
    if (rl == role::PING)
      send_pool = {
          rte_pktmbuf_pool_create("SEND_POOL", NUM_MBUFS, MEMPOOL_CACHE_SIZE, 0,
                                  RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()),
          &rte_mempool_free};
    port_init_cmdline(this, argc, argv);
  }

  int configure() {
    auto &pkt_config = config.pkt_config;
    rte_eth_conf port_conf{};
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t port = port_id;
    uint16_t q = 0;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    if (!rte_eth_dev_is_valid_port(port))
      return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
      printf("Error during getting device (port %u) info: %s\n", port,
             strerror(-retval));
      return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
      port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    if (dev_info.tx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
      port_conf.txmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
    if (dev_info.tx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
      port_conf.txmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;

    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
      port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
      port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

    pkt_config.ipv4.chcksum_offload =
        dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
    pkt_config.udp.chcksum_offload =
        dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM;

    pkt_config.ipv4.rx_chcksum_offload =
        dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
    pkt_config.udp.rx_chcksum_offload =
        dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
      return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
      return retval;
    rxconf = dev_info.default_rxconf;
    rxconf.offloads = port_conf.rxmode.offloads;
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), &rxconf, mbuf_pool.get());
    if (retval < 0)
      return retval;
    rx_queue = q;
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                    rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
      return retval;
    tx_queue = q;
    retval = rte_eth_dev_start(port);
    rte_eth_macaddr_get(port, &pkt_config.eth.src_mac);
    if (retval < 0)
      return retval;
    return 0;
  }
  ~port_info() { 
      rte_eth_dev_stop(port_id); 
      rte_free(statistics);
      rte_free(submit_statistics);
  }
} __rte_cache_aligned;
