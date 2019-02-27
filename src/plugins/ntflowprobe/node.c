/*
 * node.c - ipfix probe graph node
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/crc32.h>
#include <vppinfra/error.h>
#include <ntflowprobe/ntflowprobe.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip6_packet.h>
#include <vlibmemory/api.h>
#include <vnet/flow/flow.h>

/**
 * @file flow record generator input graph node
 */

typedef struct
{
  u8 packet_data[64];
} ntflowprobe_trace_t;


/* packet trace format function */
static u8 *
format_ntflowprobe_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ntflowprobe_trace_t *t = va_arg (*args, ntflowprobe_trace_t *);

  s = format (s, "%U",
          format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

vlib_node_registration_t ntflowprobe_input_node;

/* No counters at the moment */
#define foreach_ntflowprobe_error           \
_(MEMORY, "Flow table allocation error")

typedef enum
{
#define _(sym,str) NTFLOWPROBE_ERROR_##sym,
  foreach_ntflowprobe_error
#undef _
    NTFLOWPROBE_N_ERROR,
} ntflowprobe_error_t;

static char *ntflowprobe_error_strings[] = {
#define _(sym,string) string,
  foreach_ntflowprobe_error
#undef _
};

typedef enum
{
  NTFLOWPROBE_NEXT_OUTPUT,
  NTFLOWPROBE_N_NEXT,
} ntflowprobe_next_t;

#define NTFLOWPROBE_NEXT_NODES {                  \
    [NTFLOWPROBE_NEXT_OUTPUT] = "interface-output",           \
}

/*
 * NTP rfc868 : 2 208 988 800 corresponds to 00:00  1 Jan 1970 GMT
 */
#define NTP_TIMESTAMP 2208988800L

static inline u32
ntflowprobe_hash(const ntflowprobe_key_t const *k)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  u32 h = 0;

#ifdef clib_crc32c_uses_intrinsics
  h = clib_crc32c ((u8 *) k, sizeof (*k));
#else
  int i;
  u64 tmp = 0;
  for (i = 0; i < sizeof (*k) / 8; i++)
    tmp ^= ((u64 *) k)[i];

  h = clib_xxhash (tmp);
#endif

  return h >> (32 - fm->ht_log2len);
}

static ntflowprobe_entry_t *
ntflowprobe_lookup(ntflowprobe_main_t *fm,
  u32 thread_index,
  const ntflowprobe_key_t *key,
  u32 hash)
{
  clist_t *bucket = &fm->per_thread_flow_tables[thread_index][hash];
  ntflowprobe_entry_t *e;

  clist_for_each(e, bucket, hash_entry) {
    if (!memcmp(key, &e->key, sizeof(*key)))
      return e;
  }

  return NULL;
}

static ntflowprobe_entry_t *
ntflowprobe_create(ntflowprobe_main_t *fm,
  u32 thread_index,
  const ntflowprobe_key_t *key,
  u32 *index,
  u32 hash)
{
  clist_t *bucket;
  ntflowprobe_entry_t *e;

  pool_get(fm->per_thread_entry_pools[thread_index], e);
  if (!e)
    return NULL;

  *index = e - fm->per_thread_entry_pools[thread_index];
  bucket = &fm->per_thread_flow_tables[thread_index][hash];
  e->key = *key;
  clist_insert_after(bucket, &e->hash_entry);
  clist_insert_before(&fm->per_thread_flow_lists[thread_index], &e->list_entry);
  fm->per_thread_table_entries[thread_index]++;

  return e;
}

static ntflowprobe_config_t*
find_config(u32 rx_sw_if_index)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  int i;

  for (i = 0; i < vec_len(fm->configs); i++) {
    if (fm->configs[i].sw_if_idxs[0] == ~0U)
      continue;
    if (rx_sw_if_index == fm->configs[i].sw_if_idxs[0] ||
        rx_sw_if_index == fm->configs[i].sw_if_idxs[1])
      return &fm->configs[i];
  }
  return NULL;
}

static int
ntflowprobe_handle_packet(vlib_main_t *vm, vlib_node_runtime_t * node,
                          vlib_buffer_t *b, ntflowprobe_config_t *config,
                          u8 rx_if_idx)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  vnet_main_t *vnm = fm->vnet_main;
  u32 thread_index = vm->thread_index - 1;
  ethernet_header_t *eh = vlib_buffer_get_current(b);
  ntflowprobe_key_t key;
  ntflowprobe_entry_t *e;
  u32 flow_index;
  u16 etype = clib_net_to_host_u16(eh->type);
  ip4_header_t *ip4 = 0;
  ip6_header_t *ip6 = 0;
  udp_header_t *udp = 0;
  tcp_header_t *tcp = 0;
  u8 tcp_flags = 0;
  vnet_flow_t flow;
  vnet_device_class_t *dev_class;
  vnet_hw_interface_t *hi;
  uword private_data;
  u32 dl_sw_if = config->sw_if_idxs[rx_if_idx];
  u32 ul_sw_if = config->sw_if_idxs[rx_if_idx^1];
  u32 hash;


  if (etype != ETHERNET_TYPE_IP4 && etype != ETHERNET_TYPE_IP6)
    return 0;

  memset(&key, 0, sizeof(key));

  if (etype == ETHERNET_TYPE_IP4) {
    ip4 = (ip4_header_t *)(eh + 1);

    if (ip4->protocol == IP_PROTOCOL_TCP)
      tcp = (tcp_header_t *)(ip4 + 1);
    else if (ip4->protocol == IP_PROTOCOL_UDP)
      udp = (udp_header_t *)(ip4 + 1);
    else
      return 0;

    key.src_address.ip4.as_u32 = rx_if_idx ? ip4->dst_address.as_u32 : ip4->src_address.as_u32;
    key.dst_address.ip4.as_u32 = rx_if_idx ? ip4->src_address.as_u32 : ip4->dst_address.as_u32;
    key.protocol = ip4->protocol;
  } else {
    ip6 = (ip6_header_t *)(eh + 1);

    if (ip6->protocol == IP_PROTOCOL_TCP)
      tcp = (tcp_header_t *)(ip6 + 1);
    else if (ip6->protocol == IP_PROTOCOL_UDP)
      udp = (udp_header_t *)(ip6 + 1);
    else
      return 0;

    key.src_address.as_u64[0] = rx_if_idx ? ip6->dst_address.as_u64[0] : ip6->src_address.as_u64[0];
    key.src_address.as_u64[1] = rx_if_idx ? ip6->dst_address.as_u64[1] : ip6->src_address.as_u64[1];
    key.dst_address.as_u64[0] = rx_if_idx ? ip6->src_address.as_u64[0] : ip6->dst_address.as_u64[0];
    key.dst_address.as_u64[1] = rx_if_idx ? ip6->src_address.as_u64[1] : ip6->dst_address.as_u64[1];
    key.protocol = ip6->protocol;
  }

  key.config = config;
  clib_memcpy(key.dst_mac, rx_if_idx ? eh->dst_address : eh->src_address, 6);
  clib_memcpy(key.src_mac, rx_if_idx ? eh->src_address : eh->dst_address, 6);
  key.ethertype = eh->type;

  if (tcp) {
    key.src_port = rx_if_idx ? tcp->dst_port : tcp->src_port;
    key.dst_port = rx_if_idx ? tcp->src_port : tcp->dst_port;
    tcp_flags = tcp->flags;
  } else if (udp) {
    key.src_port = rx_if_idx ? udp->dst_port : udp->src_port;
    key.dst_port = rx_if_idx ? udp->src_port : udp->dst_port;
  }

  hash = ntflowprobe_hash(&key);
  e = ntflowprobe_lookup(fm, thread_index, &key, hash);
  if (!e) {
    e = ntflowprobe_create(fm, thread_index, &key, &flow_index, hash);
    if (!e) {
      vlib_node_increment_counter(vm, node->node_index, NTFLOWPROBE_ERROR_MEMORY, 1);
      return -1;
    }
    e->pkts_1 = e->pkts_2 = 0;
    e->octets_1 = e->octets_2 = 0;
    e->tcp_flags_1 = e->tcp_flags_2 = 0;
    e->first_time_stamp = vnet_buffer(b)->intf.timestamp;
    e->rx_if_idx = rx_if_idx;

    if (fm->enable_hw_accel) {
      flow.index = flow_index;
      flow.actions = VNET_FLOW_ACTION_REDIRECT_TO_INTERFACE;
      flow.redirect_hw_interface = vnet_get_sw_interface(vnm, ul_sw_if)->hw_if_index;
      key2flow(&key, &flow);
      /* write flow */
      hi = vnet_get_hw_interface (vnm, vnet_get_sw_interface(vnm, dl_sw_if)->hw_if_index);
      dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
      dev_class->flow_ops_function(vnm, VNET_FLOW_DEV_OP_ADD_FLOW,
				     hi->dev_instance, vnet_buffer(b)->intf.queue_id, &flow, &private_data);
    }
  }

  if (rx_if_idx == 0) {
    /* Up stream */
    e->pkts_1++;
    e->octets_1 += b->current_length;
    e->tcp_flags_1 |= tcp_flags;
  } else {
    /* Down stream */
    e->pkts_2++;
    e->octets_2 += b->current_length;
    e->tcp_flags_2 |= tcp_flags;
  }

  return 0;
}

uword
ntflowprobe_input_node_fn(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  ntflowprobe_next_t next_index;
  timestamp_nsec_t timestamp;

  unix_time_now_nsec_fraction (&timestamp.sec, &timestamp.nsec);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
  {
    u32 src_if0, src_if1;
    u8 dst_if_idx0, dst_if_idx1;
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from >= 2 && n_left_to_next >= 2)
    {
      u32 next0 = NTFLOWPROBE_NEXT_OUTPUT;
      u32 next1 = NTFLOWPROBE_NEXT_OUTPUT;
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      ntflowprobe_config_t *c0, *c1;

      /* Prefetch next iteration. */
      {
        vlib_buffer_t *p2, *p3;

        p2 = vlib_get_buffer (vm, from[2]);
        p3 = vlib_get_buffer (vm, from[3]);

        vlib_prefetch_buffer_header (p2, LOAD);
        vlib_prefetch_buffer_header (p3, LOAD);

        CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      /* speculatively enqueue b0 and b1 to the current next frame */
      to_next[0] = bi0 = from[0];
      to_next[1] = bi1 = from[1];
      from += 2;
      to_next += 2;
      n_left_from -= 2;
      n_left_to_next -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
        ntflowprobe_trace_t *t = vlib_add_trace(vm, node, b0, sizeof(*t));
        clib_memcpy(t, vlib_buffer_get_current(b0), sizeof(t->packet_data));
      }
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
      {
        ntflowprobe_trace_t *t = vlib_add_trace(vm, node, b1, sizeof(*t));
        clib_memcpy (t, vlib_buffer_get_current(b1), sizeof(t->packet_data));
      }

      src_if0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
      src_if1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
      /* Find destination interfaces */
      c0 = find_config(src_if0);
      c1 = find_config(src_if1);

      if (c0) {
        dst_if_idx0 = vnet_buffer(b0)->sw_if_index[VLIB_RX] == c0->sw_if_idxs[0] ? 1 : 0;
        ntflowprobe_handle_packet(vm, node, b0, c0, dst_if_idx0^1);
        /* Set destination interface */
        vnet_buffer(b0)->sw_if_index[VLIB_TX] = c0->sw_if_idxs[dst_if_idx0];
      }

      if (c1) {
        dst_if_idx1 = vnet_buffer(b1)->sw_if_index[VLIB_RX] == c1->sw_if_idxs[0] ? 1 : 0;
        ntflowprobe_handle_packet(vm, node, b1, c1, dst_if_idx1^1);
        /* Set destination interface */
        vnet_buffer(b1)->sw_if_index[VLIB_TX] = c1->sw_if_idxs[dst_if_idx1];
      }

      /* verify speculative enqueues, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                       to_next, n_left_to_next,
                       bi0, bi1, next0, next1);
    }

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ntflowprobe_config_t *c;
      u32 next0 = NTFLOWPROBE_NEXT_OUTPUT;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      src_if0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
      /* Find destination interfaces */
      c = find_config(src_if0);

      if (c) {
        dst_if_idx0 = vnet_buffer(b0)->sw_if_index[VLIB_RX] == c->sw_if_idxs[0] ? 1 : 0;
        ntflowprobe_handle_packet(vm, node, b0, c, dst_if_idx0^1);
        /* Find destination interface */
        vnet_buffer(b0)->sw_if_index[VLIB_TX] = c->sw_if_idxs[dst_if_idx0];
      }

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                       to_next, n_left_to_next,
                       bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ntflowprobe_input_node) = {
  .function = ntflowprobe_input_node_fn,
  .name = "ntflowprobe-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ntflowprobe_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ntflowprobe_error_strings),
  .error_strings = ntflowprobe_error_strings,
  .n_next_nodes = NTFLOWPROBE_N_NEXT,
  .next_nodes = NTFLOWPROBE_NEXT_NODES,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
