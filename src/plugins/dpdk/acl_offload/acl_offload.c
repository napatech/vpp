/*
 * Copyright (c) 2018 Napatech A/S and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/unix/cj.h>
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <dpdk/device/dpdk.h>
#include <rte_flow.h>
#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>
#include <plugins/acl/acl.h>
#include <arpa/inet.h>

typedef struct offload_s {
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[3];
	union {
		struct rte_flow_item_ipv4 ipv4;
		struct rte_flow_item_ipv6 ipv6;
	} l3_spec, l3_mask, l3_last;
	union {
		struct rte_flow_item_tcp tcp;
		struct rte_flow_item_udp udp;
	} l4_spec, l4_mask, l4_last;
	struct rte_flow_action_mark flow_action_mark;
  union {
    struct rte_flow_action_rss flow_action_rss;
    uint16_t queues[1024]; // Needed by queue array inside flow_action_rss
  };
} offload_t;


#define PREFIX_TO_IPV6_MASK(d, p)                  \
do {                                               \
    int i;                                         \
    for (i = 0; i < 16; i++) {                     \
      if (((i + 1) * 8) <= p) {                    \
        d[i] = 0xFF;                               \
      } else {                                     \
        d[i] = (0xff - ((1 << (8 - (p % 8))) - 1));\
        break;                                     \
      }                                            \
    }                                              \
} while (0)

#define PREFIX_TO_IPV4_MASK(d, p)                  \
do {                                               \
     d = p ? htonl((0xFFFFFFFF -                   \
      ((1 << (32 - p)) - 1))) : 0;                 \
} while (0)

void convert_acl_to_rte_flow(dpdk_device_t *xd , acl_rule_t *rule, offload_t *ofl)
{
  memset(ofl, 0, sizeof(offload_t));
  ofl->attr.ingress = 1;
  if (! rule->is_ipv6) {
    if ((rule->src.ip4.data_u32 == 0) && (rule->dst.ip4.data_u32 == 0)) {
      /* Only apply L3 type */
      PREFIX_TO_IPV4_MASK(ofl->l3_mask.ipv4.hdr.src_addr, 32);
      PREFIX_TO_IPV4_MASK(ofl->l3_last.ipv4.hdr.src_addr, 32);
      inet_pton(AF_INET, "1.1.1.1", &(ofl->l3_spec.ipv4.hdr.src_addr));
      ofl->pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
      ofl->pattern[0].spec = &ofl->l3_spec.ipv4;
      ofl->pattern[0].last = &ofl->l3_last.ipv4;
      ofl->pattern[0].mask = &ofl->l3_mask.ipv4;
    } else {
      ofl->l3_spec.ipv4.hdr.src_addr = rule->src.ip4.data_u32;
      ofl->l3_spec.ipv4.hdr.dst_addr = rule->dst.ip4.data_u32;
      PREFIX_TO_IPV4_MASK(ofl->l3_mask.ipv4.hdr.src_addr, rule->src_prefixlen);
      PREFIX_TO_IPV4_MASK(ofl->l3_mask.ipv4.hdr.dst_addr, rule->dst_prefixlen);
      ofl->pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
      ofl->pattern[0].spec = &ofl->l3_spec.ipv4;
      ofl->pattern[0].last = NULL;
      ofl->pattern[0].mask = &ofl->l3_mask.ipv4;
    }
  } else {
    if (((rule->src.ip6.as_u64[0] | rule->src.ip6.as_u64[1]) == 0L) &&
        ((rule->dst.ip6.as_u64[0] | rule->dst.ip6.as_u64[1]) == 0L)) {
      /* Only apply L3 type */
      PREFIX_TO_IPV6_MASK(ofl->l3_mask.ipv6.hdr.src_addr, 128);
      PREFIX_TO_IPV6_MASK(ofl->l3_last.ipv6.hdr.src_addr, 128);
      ofl->pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV6;
      ofl->pattern[0].spec = &ofl->l3_spec.ipv6;
      ofl->pattern[0].last = &ofl->l3_last.ipv6;
      ofl->pattern[0].mask = &ofl->l3_mask.ipv6;
    } else {
      memcpy(ofl->l3_spec.ipv6.hdr.src_addr, rule->src.ip6.as_u8, 16);
      memcpy(ofl->l3_spec.ipv6.hdr.dst_addr, rule->dst.ip6.as_u8, 16);
      PREFIX_TO_IPV6_MASK(ofl->l3_mask.ipv6.hdr.src_addr, rule->src_prefixlen);
      PREFIX_TO_IPV6_MASK(ofl->l3_mask.ipv6.hdr.dst_addr, rule->dst_prefixlen);
      ofl->pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV6;
      ofl->pattern[0].spec = &ofl->l3_spec.ipv6;
      ofl->pattern[0].last = NULL;
      ofl->pattern[0].mask = &ofl->l3_mask.ipv6;
    }
	}
	if (rule->proto == 6) {
		ofl->l4_spec.tcp.hdr.src_port = rule->src_port_or_type_first;
		ofl->l4_spec.tcp.hdr.dst_port = rule->dst_port_or_code_first;
		ofl->l4_last.tcp.hdr.src_port = rule->src_port_or_type_last;
		ofl->l4_last.tcp.hdr.dst_port = rule->dst_port_or_code_last;
    if (rule->src_port_or_type_first | rule->src_port_or_type_last) {
      ofl->l4_mask.tcp.hdr.src_port = 0xFFFF;
    }
    if (rule->dst_port_or_code_first | rule->dst_port_or_code_last) {
      ofl->l4_mask.tcp.hdr.dst_port = 0xFFFF;
    }
		ofl->pattern[1].type = RTE_FLOW_ITEM_TYPE_TCP;
		ofl->pattern[1].spec = &ofl->l4_spec.tcp;
		ofl->pattern[1].last = &ofl->l4_last.tcp;
		ofl->pattern[1].mask = &ofl->l4_mask.tcp;
	} else if (rule->proto == 17) {
		ofl->l4_spec.udp.hdr.src_port = rule->src_port_or_type_first;
		ofl->l4_spec.udp.hdr.dst_port = rule->dst_port_or_code_first;
		ofl->l4_last.udp.hdr.src_port = rule->src_port_or_type_last;
		ofl->l4_last.udp.hdr.dst_port = rule->dst_port_or_code_last;
    if (rule->src_port_or_type_first | rule->src_port_or_type_last) {
      ofl->l4_mask.udp.hdr.src_port = 0xFFFF;
    }
    if (rule->dst_port_or_code_first | rule->dst_port_or_code_last) {
      ofl->l4_mask.udp.hdr.dst_port = 0xFFFF;
    }
		ofl->pattern[1].type = RTE_FLOW_ITEM_TYPE_UDP;
		ofl->pattern[1].spec = &ofl->l4_spec.udp;
		ofl->pattern[1].last = &ofl->l4_last.udp;
		ofl->pattern[1].mask = &ofl->l4_mask.udp;
	} else {
    ofl->pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    ofl->pattern[1].spec = NULL;
    ofl->pattern[1].last = NULL;
    ofl->pattern[1].mask = NULL;
  }
	ofl->pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
	ofl->pattern[2].spec = NULL;
	ofl->pattern[2].last = NULL;
	ofl->pattern[2].mask = NULL;

	/* Prepare the action stack */
  int i;
 	ofl->flow_action_rss.num = xd->rx_q_used;
	for (i = 0; i < xd->rx_q_used; i++) {
		ofl->flow_action_rss.queue[i] = i;
	}
	ofl->flow_action_rss.rss_conf = NULL; // Hack. Not sure all NICs support this
  ofl->actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	ofl->actions[0].conf = &ofl->flow_action_rss;
	ofl->flow_action_mark.id = rule->is_permit ? VLIB_BUFFER_ACL_PERMIT : VLIB_BUFFER_ACL_DROP;
  ofl->actions[1].type = RTE_FLOW_ACTION_TYPE_MARK;
	ofl->actions[1].conf = &ofl->flow_action_mark;
	ofl->actions[2].type = RTE_FLOW_ACTION_TYPE_END;
	ofl->actions[2].conf = NULL;
}

int dpdk_acl_offload_supported(u32 sw_if_index)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_sw_interface_t *swi = vnet_get_sw_interface (dm->vnet_main, sw_if_index);
  vnet_hw_interface_t *hwi = vnet_get_hw_interface (dm->vnet_main, swi->hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hwi->dev_instance);
  int rv = rte_eth_dev_filter_supported(xd->device_index, RTE_ETH_FILTER_GENERIC);
  return rv;
}

void dpdk_acl_offload_add_del(void **handle, acl_rule_t *rule, u32 sw_if_index, u8 is_input, u8 is_add)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_sw_interface_t *swi = vnet_get_sw_interface (dm->vnet_main, sw_if_index);
  vnet_hw_interface_t *hwi = vnet_get_hw_interface (dm->vnet_main, swi->hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hwi->dev_instance);
	struct rte_flow_error rte_flow_error;
  offload_t ofl;

  if (! is_input) {
    /* output ACL is not supported */
    return;
  }
  if (is_add) {
    if (rule->is_permit >= 2) {
      /* We don't support permit+reflect just yet */
      return;
    }
    convert_acl_to_rte_flow(xd, rule, &ofl);
    *handle = (void*)rte_flow_create(xd->device_index, &ofl.attr, ofl.pattern, ofl.actions, &rte_flow_error);
		if (*handle == NULL) {
		  printf("rte_flow_create failed on port %d: %d -> %s\n",
        xd->device_index, rte_flow_error.type, rte_flow_error.message);
    }
  } else {
    if (handle && *handle) {
		  if (rte_flow_destroy(xd->device_index, *handle, &rte_flow_error) != 0) {
		    printf("rte_flow_destroy failed on port %d: %d -> %s\n",
          xd->device_index, rte_flow_error.type, rte_flow_error.message);
      }
      *handle = NULL;
    }
  }
}
