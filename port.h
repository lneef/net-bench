#pragma once
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

#include "statistics.h"

#define BURST_SIZE 32
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define MEMPOOL_CACHE_SIZE 256
#define NUM_MBUFS 8191
#define NUM_SENDBUF (2 * TX_RING_SIZE -  1)

#define ETHER_SIZE (RTE_ETHER_MAX_LEN + RTE_PKTMBUF_HEADROOM)
#define JUMBO_SIZE (RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM)
enum role{PING, PONG};

struct eth_config {
  struct rte_ether_addr src_mac;
  struct rte_ether_addr dst_mac;
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
  struct eth_config eth;
  struct ipv4_config ipv4;
  struct udp_config udp;
  uint32_t frame_size;
};

struct port_info {
  uint16_t port_id;
  uint16_t burst_size;
  uint16_t rx_queue;
  uint16_t tx_queue;
  uint16_t ctrl_queue;
  uint64_t bps;
  uint64_t rtime;
  struct stat *statistics;
  struct submit_stat *submit_statistics;
  struct packet_config pkt_config;
  struct rte_mempool *mbuf_pool;
  struct rte_mempool *ctrl_pool;
  struct rte_mempool *send_pool;
} __rte_cache_aligned;

int port_info_ctor(struct port_info **info, enum role role, int argc,
                   char **argv);

int port_info_dtor(struct port_info *info);
