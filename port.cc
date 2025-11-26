#include <cstdlib>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>

#include <string_view>
#include <unordered_map>

#include "port.h"

static std::unordered_map<std::string_view, mode> modes{
    {"SEND", mode::SEND},
    {"SDRV", mode::SDRV},
    {"RECV", mode::RECV},
    {"RVSD", mode::RVSD},
};

void port_init_cmdline(port_info *info, int argc, char **argv) {
  int opt, option_index;
  auto &config = info->config;
  auto &pkt_config = config.pkt_config;
  static const struct option long_options[] = {
      {"dport", required_argument, 0, 0},  {"sport", required_argument, 0, 0},
      {"dip", required_argument, 0, 0},    {"sip", required_argument, 0, 0},
      {"bps", required_argument, 0, 0},    {"rt", required_argument, 0, 0},
      {"bs", required_argument, 0, 0},     {"dmac", required_argument, 0, 0},
      {"mode", required_argument, 0, 0}, {0, 0, 0, 0}};
  while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) !=
         -1) {
    if (opt == '?')
      continue;
    switch (option_index) {
    case 0:
      pkt_config.udp.dst_port = atoi(optarg);
      break;
    case 1:
      pkt_config.udp.src_port = atoi(optarg);
      break;
    case 2:
      pkt_config.ipv4.dst_ip = inet_addr(optarg);
      break;
    case 3:
      pkt_config.ipv4.src_ip = inet_addr(optarg);
      break;
    case 4:
      config.bps = atol(optarg);
      break;
    case 5:
      config.rtime = atol(optarg);
      break;
    case 6:
      config.burst_size = atoi(optarg);
      break;
    case 7:
      rte_ether_unformat_addr(optarg, &pkt_config.eth.dst_mac);
      break;
    case 8:
      config.opmode = modes[optarg];
    default:
      break;
    }
  }
}
