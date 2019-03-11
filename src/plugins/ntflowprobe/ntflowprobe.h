/*
 * ntflowprobe.h - ipfix probe plug-in header file
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_ntflowprobe_h__
#define __included_ntflowprobe_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/flow_report_classify.h>
#include <vnet/flow/flow.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include "clist.h"

/**
 * @file
 * @brief flow-per-packet plugin header file
 */

/* Default timers in seconds */
#define NTFLOWPROBE_TIMER_ACTIVE   (15)
#define NTFLOWPROBE_TIMER_PASSIVE  120	// XXXX: FOR TESTING (30*60)
#define NTFLOWPROBE_LOG2_HASHBUCKETS  (16)
#define NTFLOWPROBE_NFLOWS (100000000) /* One hundred million flows supported */

enum ntflowprobe_l3_protocol_e {
  NTFP_PROTO_IP4 = 0,
  NTFP_PROTO_IP6,
  NTFP_PROTO_MAX
};

typedef struct {
  vlib_buffer_t *buf;
  u64 buf_time;
  u32 seq_delta;
} ntflowprobe_ipfix_thread_data_t;

typedef struct {
  ntflowprobe_ipfix_thread_data_t *thread_data;
  u16 data_set_offset;
} ntflowprobe_protocol_data_t;

typedef struct {
  u32 sw_if_idxs[2];
  ip4_address_t collector;
  ip4_address_t src;
  ntflowprobe_protocol_data_t pdata[NTFP_PROTO_MAX];
  u32 *sequence_number;
} ntflowprobe_config_t;


typedef struct __attribute__ ((aligned (8))) {
  ntflowprobe_config_t *config;
  u8 src_mac[6];
  u8 dst_mac[6];
  u16 ethertype;
  ip46_address_t src_address;
  ip46_address_t dst_address;
  u8 protocol;
  u16 src_port;
  u16 dst_port;
} ntflowprobe_key_t;

typedef struct {
  ntflowprobe_key_t key;
  clist_t hash_entry;
  clist_t list_entry;
  u64 first_time_stamp;
  /* state */
  u64 pkts_1;
  u64 pkts_2;
  u64 octets_1;
  u64 octets_2;
  u64 flow_start;
  u64 flow_end;
  u16 tcp_flags_1;
  u16 tcp_flags_2;
  u8 rx_if_idx;
  u8 hw_enabled;
} ntflowprobe_entry_t;

typedef struct
{
  u32 sec;
  u32 nsec;
} timestamp_nsec_t;

typedef struct
{
  ntflowprobe_entry_t *entry_pool;
  clist_t *flow_table;
  clist_t flow_list;
  clist_t remove_list;
  /* Status */
  u32 table_entries;
  /* Debug */
  u32 last_del;
  u32 max_diff;
  u8 pad[CLIB_CACHE_LINE_BYTES];
} ntflowprobe_main_thread_data_t;

typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /** Time reference pair */
  u64 nanosecond_time_0;
  f64 vlib_time_0;

  /** Per CPU flow-state */
  u8 ht_log2len;		/* Hash table size is 2^log2len */
  u32 **hash_per_worker;

  bool initialized;
  bool disabled;
  bool enable_hw_accel;

  ntflowprobe_config_t *configs;

  ntflowprobe_main_thread_data_t *tdata;

  u32 pool_size;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} ntflowprobe_main_t;

extern ntflowprobe_main_t ntflowprobe_main;

u8 *format_ntflowprobe_entry(u8 * s, va_list * args);
void key2flow(ntflowprobe_key_t *key, vnet_flow_t *flow);

#define NTFLOWPROBE_PLUGIN_BUILD_VER "0.1"

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
