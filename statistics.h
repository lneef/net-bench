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
  uint64_t subitted;
} __rte_cache_aligned;

#endif 
