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
 * @file flow record generator graph node
 */

/* Error counters */
#define foreach_ntflowprobe_error           \
_(MEMORY, "Buffer allocation error")

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

/* packet trace format function */
static u8 *
format_ntflowprobe_flow_trace (u8 * s, va_list * args)
{
  return s;
}

#define NTFLOWPROBE_IPFIX_MTU 1300

struct ntflowprobe_packet_t {
  ip4_header_t ip;
  udp_header_t udp;
  union {
    struct {
      ipfix_message_header_t iph;
      ipfix_set_header_t ips;
      ipfix_template_header_t ith;
    } ipfix;
  };
};

#if 0
static u64
to_ntp_nano_time_net(u64 unix_ns)
{
  u64 sec, nsec;

  sec = unix_ns/1000000000;
  nsec = unix_ns - (sec*1000000000);

  sec += 2208988800U;

  return ((u64)clib_host_to_net_u32(nsec) << 32) + clib_host_to_net_u32(sec);
}
#endif

static vlib_buffer_t*
get_buffer(vlib_main_t *vm, vlib_node_runtime_t * node, ntflowprobe_config_t *conf,
  enum ntflowprobe_l3_protocol_e rectype)
{
  u32 bi;
  vlib_buffer_t *b;
  vlib_buffer_free_list_t *fl;
  struct ntflowprobe_packet_t *p;
  ntflowprobe_thread_data_t *td = &conf->pdata[rectype].thread_data[vm->thread_index-1];

  if (conf->pdata[rectype].thread_data[vm->thread_index-1].buf)
    return conf->pdata[rectype].thread_data[vm->thread_index-1].buf;

  /* Allocate and initialize a new buffer */
  if (vlib_buffer_alloc(vm, &bi, 1) != 1) {
    vlib_node_increment_counter(vm, node->node_index, NTFLOWPROBE_ERROR_MEMORY, 1);
    return NULL;
  }

  b = vlib_get_buffer(vm, bi);
  td->buf = b;
  td->buf_time = vlib_time_now(vm);
  td->seq_delta = 0;

  fl = vlib_buffer_get_free_list(vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list(b, fl);

  b->current_data = 0;

  p = vlib_buffer_get_current(b);

  p->ip.ip_version_and_header_length = 0x45;
  p->ip.ttl = 254;
  p->ip.protocol = IP_PROTOCOL_UDP;
  p->ip.flags_and_fragment_offset = 0;
  p->ip.src_address = conf->src;
  p->ip.dst_address = conf->collector;
  p->udp.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  p->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  p->udp.checksum = 0;

  ipfix_message_header_t *h = &p->ipfix.iph;
  h->export_time = 0; /* TODO: set current time */
  h->sequence_number = 0;
  h->domain_id = clib_host_to_net_u32(1);

  ipfix_template_header_t *t = &p->ipfix.ith;
  t->id_count = ipfix_id_count(256, 11);

  ipfix_field_specifier_t *fs = (ipfix_field_specifier_t*)(t + 1);
  (fs++)->e_id_length = ipfix_e_id_length(0, ethernetType, 2);
  if (rectype == NTFP_PROTO_IP4) {
    (fs++)->e_id_length = ipfix_e_id_length(0, sourceIPv4Address, 4);
    (fs++)->e_id_length = ipfix_e_id_length(0, destinationIPv4Address, 4);
  } else {
    (fs++)->e_id_length = ipfix_e_id_length(0, sourceIPv4Address, 16);
    (fs++)->e_id_length = ipfix_e_id_length(0, destinationIPv4Address, 16);
  }
  (fs++)->e_id_length = ipfix_e_id_length(0, protocolIdentifier, 1);
  (fs++)->e_id_length = ipfix_e_id_length(0, sourceTransportPort, 2);
  (fs++)->e_id_length = ipfix_e_id_length(0, destinationTransportPort, 2);
  (fs++)->e_id_length = ipfix_e_id_length(0, packetDeltaCount, 8);
  (fs++)->e_id_length = ipfix_e_id_length(0, octetDeltaCount, 8);
  (fs++)->e_id_length = ipfix_e_id_length(0, tcpControlBits, 2);
  (fs++)->e_id_length = ipfix_e_id_length(0, flowStartMilliseconds, 8);
  (fs++)->e_id_length = ipfix_e_id_length(0, flowEndMilliseconds, 8);

  ipfix_set_header_t *s = &p->ipfix.ips;
  s->set_id_length = ipfix_set_id_length(2, (u8*)fs - (u8*)s);

  conf->pdata[rectype].data_set_offset = (u8*)fs - (u8*)p;

  b->current_length = (u8*)(fs + 1) - (u8*)p;
  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  vnet_buffer(b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer(b)->sw_if_index[VLIB_TX] = ~0;

  return b;
}

static void
send_ipfix_packet(vlib_main_t *vm, vlib_buffer_t *b, ntflowprobe_config_t *conf,
  enum ntflowprobe_l3_protocol_e rectype)
{
  ntflowprobe_thread_data_t *td = &conf->pdata[rectype].thread_data[vm->thread_index-1];
  u32 *to_next;
  u32 bi;
  vlib_frame_t *f;
  u32 dummy;
  struct ntflowprobe_packet_t *p;

  /* Send IPFIX packet */
  p = vlib_buffer_get_current(b);
  p->ip.length = clib_host_to_net_u16 (b->current_length);
  p->ip.checksum = ip4_header_checksum (&p->ip);
  p->udp.length = clib_host_to_net_u16 (b->current_length - sizeof(ip4_header_t));

  ipfix_message_header_t *h = &p->ipfix.iph;
  h->version_length = version_length(b->current_length - sizeof(ip4_header_t) -
      sizeof(udp_header_t));

  unix_time_now_nsec_fraction(&h->export_time, &dummy);
  h->export_time = clib_host_to_net_u32(h->export_time);
  h->sequence_number = clib_host_to_net_u32(clib_smp_atomic_add(conf->sequence_number, td->seq_delta));

  ipfix_set_header_t *s =
      (ipfix_set_header_t*)((u8*)p + conf->pdata[rectype].data_set_offset);
  s->set_id_length = ipfix_set_id_length(256, (u8*)vlib_buffer_get_tail(b) - (u8*)s);

  /* Allocate frame */
  f = vlib_get_frame_to_node(vm, ip4_lookup_node.index);
  bi = vlib_get_buffer_index(vm, b);
  to_next = vlib_frame_vector_args(f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node(vm, ip4_lookup_node.index, f);
  td->buf = 0;
}

static void
add_ipfix_flow_record(vlib_main_t *vm,
  vlib_node_runtime_t * node, ntflowprobe_main_t *fm,
  ntflowprobe_config_t *conf, ntflowprobe_entry_t *e,
  flow_event_t *evt, int up)
{
  ntflowprobe_thread_data_t *td;
  enum ntflowprobe_l3_protocol_e rectype;
  vlib_buffer_t *b;
  u64 tmp;
  u8* dp;
  u64 ts;
  u64 pkts, octs;


  pkts = clib_host_to_net_u64(up ? (evt->packets_1 + e->pkts_1) : (evt->packets_2 + e->pkts_2));
  octs = clib_host_to_net_u64(up ? (evt->octets_1 + e->octets_1) : (evt->octets_2 + e->octets_2));

  if (!pkts || !octs)
    return;

  rectype = clib_net_to_host_u16(e->key.ethertype) == ETHERNET_TYPE_IP4 ?
      NTFP_PROTO_IP4 : NTFP_PROTO_IP6;

  td = &conf->pdata[rectype].thread_data[vm->thread_index-1];

  b = get_buffer(vm, node, conf, rectype);
  if (!b) {
    return;
  }

  if (rectype == NTFP_PROTO_IP4)
    dp = vlib_buffer_put_uninit(b, 49);
  else
    dp = vlib_buffer_put_uninit(b, 73);

  clib_memcpy(dp, &e->key.ethertype, 2);
  dp += 2;
  if (rectype == NTFP_PROTO_IP4) {
    clib_memcpy(dp, up ? &e->key.src_address.ip4.as_u32 : &e->key.dst_address.ip4.as_u32, 4);
    clib_memcpy(dp+4, up ? &e->key.dst_address.ip4.as_u32 : &e->key.src_address.ip4.as_u32, 4);
    dp += 8;
  } else {
    clib_memcpy(dp, up ? &e->key.src_address.ip6.as_u64 : &e->key.dst_address.ip6.as_u64, 16);
    clib_memcpy(dp+16, up ? &e->key.dst_address.ip6.as_u64 : &e->key.src_address.ip6.as_u64, 16);
    dp += 32;
  }
  *(dp++) = e->key.protocol;
  clib_memcpy(dp, up ? &e->key.src_port : &e->key.dst_port, 2);
  dp += 2;
  clib_memcpy(dp, up ? &e->key.dst_port : &e->key.src_port, 2);
  dp += 2;

  clib_memcpy(dp, &pkts, 8);
  dp += 8;

  clib_memcpy(dp, &octs, 8);
  dp += 8;

  tmp = clib_host_to_net_u16(up ? (evt->flags_1 + e->tcp_flags_1) : (evt->flags_2 + e->tcp_flags_2));
  clib_memcpy(dp, &tmp, 2);
  dp += 2;

  ts = clib_host_to_net_u64(e->first_time_stamp/1000000);
  clib_memcpy(dp, &ts, 8);
  dp += 8;

  ts = clib_host_to_net_u64(evt->time_stamp/1000000);
  clib_memcpy(dp, &ts, 8);

  td->seq_delta++;


  if (b->current_length > NTFLOWPROBE_IPFIX_MTU) {
    send_ipfix_packet(vm, b, conf, rectype);
  }
}

static void
remove_old_flows(vlib_main_t * vm, u32 thread_index, u32 queue_id)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  vnet_main_t *vnm = fm->vnet_main;
  clist_t *flow_list = &fm->per_thread_flow_lists[thread_index];
  ntflowprobe_entry_t *flow_entry, *tmp;
  vnet_device_class_t *dev_class;
  vnet_hw_interface_t *hi;
  vnet_flow_t flow;

  clist_for_each_safe(flow_entry, tmp, flow_list, list_entry) {
    if (unix_time_now_nsec() < flow_entry->first_time_stamp + 30e9) {
      break;
    }
    flow.index = flow_entry - fm->per_thread_entry_pools[thread_index];
    flow.actions = 0;
    key2flow(&flow_entry->key, &flow);
    hi = vnet_get_hw_interface (vnm,
          vnet_get_sw_interface(vnm,
            flow_entry->key.config->sw_if_idxs[0])->hw_if_index);
    dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
    dev_class->flow_ops_function(vnm, VNET_FLOW_DEV_OP_DEL_FLOW,
           hi->dev_instance, queue_id, &flow, NULL);

    clist_remove(&flow_entry->list_entry);
  }
}

void
read_and_process_flow_records(vlib_main_t * vm,
  vlib_node_runtime_t * node,
  vnet_hw_interface_t *hw,
  u32 queue_id, ntflowprobe_config_t *conf)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  vnet_main_t *vnm = fm->vnet_main;
  u32 thread_index = vm->thread_index - 1;
  vnet_device_class_t *dev_class;
  u32 flows_read = 0;
  flow_event_t evt;
  ntflowprobe_entry_t *e;

  /* TODO: remove when FPGA can time out flows */
  remove_old_flows(vm, thread_index, queue_id);

  dev_class = vnet_get_device_class (vnm, hw->dev_class_index);

  while (dev_class->flow_event_function(vnm, hw->dev_instance, queue_id, &evt) > 0) {
    ASSERT(evt.id < vec_len(fm->per_thread_entry_pools[thread_index]));
    e = &fm->per_thread_entry_pools[thread_index][evt.id];
    add_ipfix_flow_record(vm, node, fm, conf, e, &evt, 1); /* Upstream */
    add_ipfix_flow_record(vm, node, fm, conf, e, &evt, 0); /* DownStream */
    clist_remove(&e->hash_entry);
    pool_put(fm->per_thread_entry_pools[thread_index], e);
    fm->per_thread_table_entries[thread_index]--;
    flows_read++;
  }
}

uword
ntflowprobe_flow_node_fn(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ntflowprobe_config_t *conf;
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  vnet_main_t *vnm = fm->vnet_main;
  vnet_interface_main_t *ifm = &vnm->interface_main;
  vnet_hw_interface_t *hw;
  u32 thread_index = vm->thread_index;
  int i;

  if (thread_index == 0)
    return 0;

  if (!fm->initialized || fm->disabled)
    return 0;

  vec_foreach(hw, ifm->hw_interfaces) {
    vec_foreach(conf, fm->configs) {
      if (hw->sw_if_index != conf->sw_if_idxs[0] &&
          hw->sw_if_index != conf->sw_if_idxs[1]) {
        continue;
      }
      u32 queue_id = 0, *t_idx;
      vec_foreach(t_idx, hw->input_node_thread_index_by_queue) {
        if (*t_idx == thread_index) {
          read_and_process_flow_records(vm, node, hw, queue_id, conf);
        }
        queue_id++;
      }

      /* Send old ipfix packets */
      for (i = 0; i < NTFP_PROTO_MAX; i++) {
        ntflowprobe_thread_data_t *td = &conf->pdata[i].thread_data[thread_index-1];
        if (td->buf && (vlib_time_now(vm) - td->buf_time) >= 5) {
          send_ipfix_packet(vm, td->buf, conf, i);
        }
      }
    }
  }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ntflowprobe_flow_node) = {
  .function = ntflowprobe_flow_node_fn,
  .name = "ntflowprobe-flow",
  .sibling_of = "device-input",
  .format_trace = format_ntflowprobe_flow_trace,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .n_errors = ARRAY_LEN(ntflowprobe_error_strings),
  .error_strings = ntflowprobe_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
