#ifndef STATISTICS_H
#define STATISTICS_H

#include <rte_common.h>
#include <stdint.h>

struct stat {
  uint64_t received;
  uint64_t time;
  uint64_t min;
  uint64_t cksum_incorrect;
} __rte_cache_aligned;

struct submit_stat {
  uint64_t submitted;
} __rte_cache_aligned;

struct pkt_content_rdtsc {
  uint64_t time;
} __rte_packed;

#endif 
