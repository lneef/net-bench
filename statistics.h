#ifndef STATISTICS_H
#define STATISTICS_H

#include <rte_common.h>
#include <stdint.h>

struct stat {
  uint64_t received;
  uint64_t time;
  uint64_t min;
  uint64_t cksum_incorrect;

  stat& operator+=(const stat& other){
      received += other.received;
      time += other.time;
      min += other.min;
      cksum_incorrect += other.cksum_incorrect;
      return *this;
  }
} __rte_cache_aligned;

struct submit_stat {
  uint64_t submitted;

  submit_stat& operator+=(const submit_stat& other){
      submitted += other.submitted;
      return *this;
  }

} __rte_cache_aligned;

struct __rte_packed_begin pkt_content_rdtsc {
  uint64_t time;
}__rte_packed_end;

#endif 
