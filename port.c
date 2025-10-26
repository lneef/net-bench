#include <rte_ether.h>
#include <rte_mbuf_core.h>
#include <stdlib.h>

#include "port.h"

static struct rte_eth_conf port_conf = {
    .rxmode = {.max_lro_pkt_size = RTE_ETHER_MAX_LEN,
                .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM},
    .txmode = {.mq_mode = RTE_ETH_MQ_TX_NONE}
};

static int port_init_cmdline(struct port_info *info, int argc, char **argv) {
  int opt, option_index;
  static const struct option long_options[] = {
      {"dport", required_argument, 0, 0},
      {"sport", required_argument, 0, 0},
      {"dip", required_argument, 0, 0},
      {"sip", required_argument, 0, 0},
      {"bps", required_argument, 0, 0},
      {"rt", required_argument, 0, 0},
      {"bs", required_argument, 0, 0},
      {"dmac", required_argument, 0, 0},
      {0, 0, 0, 0}};
  while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) !=
         -1) {
    if (opt == '?')
      continue;
    switch (option_index) {
    case 0:
      info->pkt_config.udp.dst_port = atoi(optarg);
      break;
    case 1:
      info->pkt_config.udp.src_port = atoi(optarg);
      break;
    case 2:
      info->pkt_config.ipv4.dst_ip = inet_addr(optarg);
      break;
    case 3:
      info->pkt_config.ipv4.src_ip = inet_addr(optarg);
      break;
    case 4:
      info->bps = atol(optarg);
      break;
    case 5:
      info->rtime = atol(optarg);
      break;
    case 6:
      info->burst_size = atoi(optarg);
      break;
    case 7:
      rte_ether_unformat_addr(optarg, &info->pkt_config.eth.dst_mac);
      break;
    default:
      break;
    }
    info->burst_size = RTE_MIN(info->burst_size, BURST_SIZE);
  }
  return 0;
}

static int port_init(struct port_info *pinfo) {
  const uint16_t rx_rings = 1, tx_rings = 1;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t port = pinfo->port_id;
  uint16_t q = 0;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf rxconf;
  struct rte_eth_txconf txconf;
  if (!rte_eth_dev_is_valid_port(port))
    return -1;

  memset(&port_conf, 0, sizeof(struct rte_eth_conf));

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

  pinfo->pkt_config.ipv4.chcksum_offload =
      dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  pinfo->pkt_config.udp.chcksum_offload =
      dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM;

  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;
  rxconf = dev_info.default_rxconf;
  retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port),
                                  &rxconf, pinfo->recv_pool);
  if (retval < 0)
    return retval;
  pinfo->rx_queue = q;
  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port),
                                  &txconf);
  if (retval < 0)
    return retval;
  pinfo->tx_queue = q;
  retval = rte_eth_dev_start(port);
  rte_eth_macaddr_get(port, &pinfo->pkt_config.eth.src_mac);
  if (retval < 0)
    return retval;
  return 0;
}

int port_info_ctor(struct port_info **info, enum role role, int argc,
                   char **argv) {
  *info = (struct port_info *)rte_calloc(NULL, 1, sizeof(struct port_info),
                                         RTE_CACHE_LINE_MIN_SIZE);
  if (!*info)
    return -1;
  (*info)->pps = UINT64_MAX;
  (*info)->burst_size = BURST_SIZE;
  (*info)->pkt_config.frame_size = RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN;
  (*info)->statistics = (struct stat *)rte_calloc(NULL, 1, sizeof(struct stat),
                                                  RTE_CACHE_LINE_MIN_SIZE);
  for (int i = 0; i < RTE_ETHER_ADDR_LEN; ++i)
    (*info)->pkt_config.eth.dst_mac.addr_bytes[i] = 0xff;
  if (port_init_cmdline(*info, argc, argv))
    return -1;
  (*info)->port_id = 0;
  if (role == ROLE_PING) {
    (*info)->mbuf_pool =
        rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MEMPOOL_CACHE_SIZE, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if ((*info)->mbuf_pool == NULL)
      return -1;
    (*info)->ctrl_pool = rte_pktmbuf_pool_create(
        "CTRL_POOL", 16, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if ((*info)->ctrl_pool == NULL)
      return -1;
  }
  (*info)->recv_pool =
      rte_pktmbuf_pool_create("RECV_POOL", NUM_MBUFS, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  return port_init(*info);
}

int port_info_dtor(struct port_info *info) {
  rte_eth_dev_stop(info->port_id);
  rte_eth_dev_close(info->port_id);
  if (info->mbuf_pool)
    rte_mempool_free(info->mbuf_pool);
  if (info->ctrl_pool)
    rte_mempool_free(info->ctrl_pool);
  if (info->recv_pool)
    rte_mempool_free(info->recv_pool);
  rte_free(info->statistics);
  rte_free(info->submit_statistics);
  rte_free(info);
  return 0;
}
