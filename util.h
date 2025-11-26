#ifndef UTIL_H
#define UTIL_H
#include <generic/rte_byteorder.h>
#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#include "port.h"

#define TTL 64
#define SWAP(a, b, T)                                                          \
  do {                                                                         \
    T temp = a;                                                                \
    a = b;                                                                     \
    b = temp;                                                                  \
  } while (0)

#define PUN(target, src, T)                                                    \
  do {                                                                         \
    rte_memcpy(target, src, sizeof(T));                                        \
  } while (0)

typedef int (*packet_ipv4)(struct port_info *, struct rte_mbuf *);

int launch_lcores(int (**lcore_fn)(void *), struct port_info *arg,
                         uint16_t cores);
#endif
