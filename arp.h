#ifndef ARP_H
#define ARP_H

#include <generic/rte_pause.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include "port.h"

#define MAX_TRIES 1024

int process_arp(struct rte_mbuf *mbuf, struct port_info *info);

int resolve_arp(struct port_info *info);

#endif // !ARP_H
