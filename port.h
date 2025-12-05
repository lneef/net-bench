#pragma once
#include <cstdint>
#include <memory>
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
#include <vector>

#include "statistics.h"

#define BURST_SIZE 32
#define MEMPOOL_CACHE_SIZE 256

#define ETHER_SIZE (RTE_ETHER_MAX_LEN + RTE_PKTMBUF_HEADROOM)
#define JUMBO_SIZE (RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM)

enum class opmode { PING, PONG, FORWARD, RECEIVE };

struct capabilities {
  bool ip_cksum_tx, ip_cksum_rx;
  bool l4_cksum_tx, l4_cksum_rx;
};

struct port_info;
struct benchmark_config {
  uint32_t sip, dip;
  uint32_t frame_size;
  uint64_t rtime;
  uint16_t burst_size;
  uint16_t flows;
  uint16_t nb_threads;
  rte_ether_addr dmac;
  opmode role;
  benchmark_config() : nb_threads(1) {}
  int port_init_cmdline(int argc, char **argv);
  int port_init(port_info &info);
};

static constexpr auto deleter = [](rte_mempool *pool) {
  if (pool)
    rte_mempool_free(pool);
};

struct thread_block {
  std::vector<uint16_t> rx_queues;
  std::vector<uint16_t> tx_queues;
  std::unique_ptr<stat> per_thread_stat;
  std::unique_ptr<submit_stat> per_thread_submit_stat;
  std::shared_ptr<rte_mempool> recv_pool;
  std::shared_ptr<rte_mempool> send_pool;

  thread_block()
      : per_thread_stat(std::make_unique<stat>()),
        per_thread_submit_stat(std::make_unique<submit_stat>()) {}

  void setup_rxqueue(uint16_t port, uint16_t nb_desc, rte_eth_rxconf &rxconf,
                     rte_mempool *pool);
  void setup_txqueue(uint16_t port, uint16_t nb_desc, rte_eth_txconf &txconf,
                     rte_mempool *pool);
};

struct port_info {
  uint16_t port_id;
  std::vector<thread_block> thread_blocks;
  capabilities caps;
  rte_ether_addr addr;

  thread_block& local() { return thread_blocks[rte_lcore_index(rte_lcore_id())]; }
  void collect_statistics(stat& statistics);

  void collect_submit_statistics(submit_stat& statistics);
};
