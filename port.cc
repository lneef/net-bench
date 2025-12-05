#include <cstdint>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>
#include <string_view>
#include <unordered_map>

#include "port.h"
static std::unordered_map<std::string_view, opmode> opmodes{
    {"PING", opmode::PING}, {"PONG", opmode::PONG}, {"FORWARD", opmode::FORWARD}, {"RECEIVE", opmode::RECEIVE}
};

static std::pair<rte_mempool*, rte_mempool*> alloc_pools(opmode role, uint16_t recv_pool_sz, uint16_t send_pool_sz){
    std::pair<rte_mempool*, rte_mempool*> pools{nullptr, nullptr};
    if(role == opmode::FORWARD || role == opmode::PING || role == opmode::PONG)
        pools.first = rte_pktmbuf_pool_create("MBUF_POOL", send_pool_sz, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(role == opmode::RECEIVE || role == opmode::PING || role == opmode::PONG)
        pools.second = rte_pktmbuf_pool_create("MBUF_POOL", recv_pool_sz, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    return pools;
}

int benchmark_config::port_init_cmdline(int argc, char **argv) {
  int opt, option_index;
  static const struct option long_options[] = {
      {"dip", required_argument, 0, 0},   {"sip", required_argument, 0, 0},
      {"framesize", required_argument, 0, 0},   {"rt", required_argument, 0, 0},
      {"bs", required_argument, 0, 0},    {"dmac", required_argument, 0, 0},
      {"mode", required_argument, 0, 0},  {"flows", required_argument, 0, 0},
      {0, 0, 0, 0}};
  while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) !=
         -1) {
    if (opt == '?')
      continue;
    switch (option_index) {
    case 0:
      dip = inet_addr(optarg);
      break;
    case 1:
      sip = inet_addr(optarg);
      break;
    case 2:
      frame_size = atol(optarg);
      break;
    case 3:
      rtime = atol(optarg);
      break;
    case 4:
      burst_size = atoi(optarg);
      break;
    case 5:
      rte_ether_unformat_addr(optarg, &dmac);
      break;
    case 6:
      role = opmodes[std::string_view(optarg, strlen(optarg))];
      break;
    case 7:
      flows = atoi(optarg);
      break;
    default:
      break;
    }
  }
  return 0;
}

int benchmark_config::port_init(port_info& info) {
  const uint16_t rx_rings = 1, tx_rings = 1;
  uint16_t nb_rxd, nb_txd;
  int retval;
  uint16_t port = info.port_id;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf rxconf;
  struct rte_eth_txconf txconf;
  if (!rte_eth_dev_is_valid_port(port))
    return -1;
  rte_eth_conf port_conf{}; 
  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port,
           strerror(-retval));
    return retval;
  }
  nb_rxd = dev_info.rx_desc_lim.nb_max;
  nb_txd = dev_info.tx_desc_lim.nb_max;

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

  info.caps.ip_cksum_tx = 
      dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
  info.caps.l4_cksum_tx =
      dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

  info.caps.ip_cksum_rx =
      dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  info.caps.ip_cksum_tx =
      dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM;

  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  info.thread_blocks.resize(nb_threads);
  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  rxconf = dev_info.default_rxconf;
  rxconf.offloads = port_conf.rxmode.offloads;
  for(auto& tb: info.thread_blocks){
      auto [send_pool, recv_pool] = alloc_pools(role, nb_rxd + burst_size, nb_txd + burst_size);
      tb.setup_txqueue(port, nb_txd, txconf, send_pool);
      tb.setup_rxqueue(port, nb_rxd, rxconf, recv_pool);
  }
  retval = rte_eth_dev_start(port);
  rte_eth_macaddr_get(port, &info.addr);
  if (retval < 0)
    return retval;
  return 0;
}


void thread_block::setup_rxqueue(uint16_t port, uint16_t nb_desc, rte_eth_rxconf& rxconf, rte_mempool* pool){
    recv_pool = {pool, deleter};
    uint16_t qid = rx_queues.size();
    if(rte_eth_rx_queue_setup(port, qid, nb_desc, rte_eth_dev_socket_id(port),
                                  &rxconf, pool))
        throw std::runtime_error("Failed to setup rxqueue\n");
    rx_queues.push_back(qid);

}

void thread_block::setup_txqueue(uint16_t port, uint16_t nb_desc, rte_eth_txconf& txconf, rte_mempool* pool){
    send_pool = {pool, deleter};
    uint16_t qid = tx_queues.size();
    if(rte_eth_tx_queue_setup(port, qid, nb_desc, rte_eth_dev_socket_id(port),
                                  &txconf))
        throw std::runtime_error("Failed to setup txqueue\n");
    tx_queues.push_back(qid);
}

void port_info::collect_statistics(stat& statistics){
    for(auto& tb : thread_blocks)
        statistics += *tb.per_thread_stat;
}

void port_info::collect_submit_statistics(submit_stat& statistics){
    for(auto& tb : thread_blocks){
        statistics += *tb.per_thread_submit_stat;
    }
}
