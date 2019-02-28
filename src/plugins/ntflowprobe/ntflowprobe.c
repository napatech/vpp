/*
 * ntflowprobe.c - ipfix probe plugin
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

/**
 * @file
 * @brief Per-packet IPFIX flow record generator plugin
 *
 * This file implements vpp plugin registration mechanics,
 * debug CLI, and binary API handling.
 */

#include <vnet/vnet.h>
//#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <ntflowprobe/ntflowprobe.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <ntflowprobe/ntflowprobe_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ntflowprobe/ntflowprobe_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ntflowprobe/ntflowprobe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ntflowprobe/ntflowprobe_all_api_h.h>
#undef vl_printfun

ntflowprobe_main_t ntflowprobe_main;

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ntflowprobe/ntflowprobe_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE fm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */
#define foreach_ntflowprobe_plugin_api_msg                           \
_(NTFLOWPROBE_ENABLE_DISABLE, ntflowprobe_enable_disable)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = NTFLOWPROBE_PLUGIN_BUILD_VER,
    .description = "Napatech Flow Probe Plugin",
};
/* *INDENT-ON* */

/* Define the per-interface configurable features */
/* *INDENT-OFF* */
VNET_FEATURE_INIT (flow_perpacket_ip4, static) =
{
  .arc_name = "device-input",
  .node_name = "ntflowprobe-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON* */

void
key2flow(ntflowprobe_key_t *key, vnet_flow_t *flow)
{
  u16 etype = clib_net_to_host_u16(key->ethertype);
  int i;

  if (etype == ETHERNET_TYPE_IP4) {
    flow->type = VNET_FLOW_TYPE_IP4_N_TUPLE;
    vnet_flow_ip4_n_tuple_t *t4 = &flow->ip4_n_tuple;
    t4->src_addr.addr = key->src_address.ip4;
    t4->src_addr.mask.data_u32 =0xffffffff;
    t4->dst_addr.addr = key->dst_address.ip4;
    t4->dst_addr.mask.data_u32 =0xffffffff;
    t4->src_port.port = key->src_port;
    t4->dst_port.port = key->dst_port;
    t4->src_port.mask = t4->dst_port.mask = 0xffff;
    t4->protocol = key->protocol;
  } else {
    flow->type = VNET_FLOW_TYPE_IP6_N_TUPLE;
    vnet_flow_ip6_n_tuple_t *t6 = &flow->ip6_n_tuple;
    clib_memcpy(&t6->src_addr.addr, &key->src_address.ip6, 16);
    clib_memcpy(&t6->dst_addr.addr, &key->dst_address.ip6, 16);
    for (i = 0; i < 2; i++) {
      t6->src_addr.mask.as_u64[i] = ~0UL;
      t6->dst_addr.mask.as_u64[i] = ~0UL;
    }
    t6->src_port.port = key->src_port;
    t6->dst_port.port = key->dst_port;
    t6->src_port.mask = t6->dst_port.mask = 0xffff;
    t6->protocol = key->protocol;
  }
}

static int
ntflowprobe_enable_disable(ntflowprobe_main_t * fm, int is_enable,
                           u32 sw_if_index1, u32 sw_if_index2,
                           ip4_address_t collector_ip,
                           ip4_address_t src_ip)
{
  ntflowprobe_config_t *cnf = NULL;
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 num_threads;
  int i, j;
  vnet_sw_interface_t *swif1 = vnet_get_sw_interface(fm->vnet_main, sw_if_index1);
  vnet_sw_interface_t *swif2 = vnet_get_sw_interface(fm->vnet_main, sw_if_index2);

  if (!swif1 || !swif2 || swif1->type != VNET_SW_INTERFACE_TYPE_HARDWARE ||
      swif2->type != VNET_SW_INTERFACE_TYPE_HARDWARE) {
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  }

  num_threads = tm->n_threads;

  if (is_enable) {
    /* Check if interfaces are already used and/or find free element*/
    int free = -1;
    for (i = 0; i < vec_len(fm->configs); i++) {
      if (fm->configs[i].sw_if_idxs[0] == ~0U) {
        if (free < 0) {
          free = i;
        }
        continue;
      }
      if (fm->configs[i].sw_if_idxs[0] == sw_if_index1 || fm->configs[i].sw_if_idxs[0] == sw_if_index2 ||
          fm->configs[i].sw_if_idxs[1] == sw_if_index1 || fm->configs[i].sw_if_idxs[1] == sw_if_index2)
        return VNET_API_ERROR_INSTANCE_IN_USE;
    }
    cnf = &fm->configs[free];

    cnf->collector = collector_ip;
    cnf->src = src_ip;
    cnf->sw_if_idxs[1] = sw_if_index2;
    cnf->sw_if_idxs[0] = sw_if_index1;
    for (i = 0; i < NTFP_PROTO_MAX; i++) {
      vec_validate(cnf->pdata[i].thread_data, num_threads);
      for (j = 0; j < num_threads; j++)
        cnf->pdata[i].thread_data[j].buf = 0;
    }

    cnf->sequence_number = clib_mem_alloc_aligned(sizeof(u32), CLIB_CACHE_LINE_BYTES);
    *cnf->sequence_number = 0;

    if (!fm->initialized) {
      fm->pool_size = NTFLOWPROBE_NFLOWS/num_threads + 1;
      /* Allocate pools and tables */
      vec_validate(fm->tdata, num_threads);
      for (i = 0; i < num_threads; i++) {
        pool_alloc(fm->tdata[i].entry_pool, fm->pool_size);
        vec_validate(fm->tdata[i].flow_table, (1 << fm->ht_log2len));
        clist_head_init(&fm->tdata[i].flow_list);
        fm->tdata[i].table_entries = 0;
        for (j = 0; j < vec_len(fm->tdata[i].flow_table); j++)
          clist_head_init(&fm->tdata[i].flow_table[j]);
      }
      fm->initialized = 1;
      fm->enable_hw_accel = 1;
    }
  }
  else
  {
    int nconf = 0;
    /* Find configuration record */
    for (i = 0; i < vec_len(fm->configs); i++) {
      if ((fm->configs[i].sw_if_idxs[0] == sw_if_index1 && fm->configs[i].sw_if_idxs[1] == sw_if_index2) ||
          (fm->configs[i].sw_if_idxs[0] == sw_if_index2 && fm->configs[i].sw_if_idxs[1] == sw_if_index1)) {
        cnf = &fm->configs[i];
      }
      if (fm->configs[i].sw_if_idxs[0] != ~0U)
        nconf++;
    }
    if (!cnf)
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;

    cnf->sw_if_idxs[0] = ~0U;

    clib_mem_free(cnf->sequence_number);
    for (j = 0; j < NTFP_PROTO_MAX; j++)
      vec_free(cnf->pdata[j].thread_data);

    if (nconf == 1) {
      fm->initialized = 0;
      /* Free resources */
      for (i = 0; i < num_threads; i++) {
        vec_free(fm->tdata[i].entry_pool);
        vec_free(fm->tdata[i].flow_table);
      }
      vec_free(fm->tdata);
    }
  }

  vnet_feature_enable_disable("device-input", "ntflowprobe-input", sw_if_index1, is_enable, 0, 0);
  vnet_feature_enable_disable("device-input", "ntflowprobe-input", sw_if_index2, is_enable, 0, 0);

  return 0;
}

static clib_error_t *
ntflowprobe_enable_disable_fn(vlib_main_t * vm, unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  int idx = 0;
  u32 sw_if_idxs[3];
  ip4_address_t collector_address, src_address;
  int ret;
  u32 enable = cmd->function_arg;

  collector_address.data_u32 = ~0U;
  src_address.data_u32 = ~0U;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "%U", unformat_vnet_sw_interface, fm->vnet_main, &sw_if_idxs[idx]))
      idx++;
    else if(unformat(input, "collector %U", unformat_ip4_address, &collector_address))
      ;
    else if(unformat(input, "src %U", unformat_ip4_address, &src_address))
      ;
    else
      break;
    if (idx >= 3)
      return clib_error_return(0, "Only two interfaces may be specified");
  }

  if (enable && collector_address.data_u32 == ~0U)
    return clib_error_return(0, "Collector IP address not specified");
  if (idx != 2)
    return clib_error_return(0, "Two interfaces must be specified");

  ret = ntflowprobe_enable_disable(fm, enable ? 1 : 0, sw_if_idxs[0],
                                   sw_if_idxs[1], collector_address, src_address);
  if (!ret)
    return 0;

  return clib_error_return_code(0, ret, 0, "Could not %s flow probe", enable ? "enable" : "disable");
}

static clib_error_t *
ntflowprobe_status_fn(vlib_main_t * vm, unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  ntflowprobe_config_t *cnf;
  ntflowprobe_main_thread_data_t *td;
  int t;

  vlib_cli_output(vm, "NtFlowProbe Status: %s", fm->initialized ? "Enabled" : "Disabled");

  vec_foreach(cnf, fm->configs) {
    if (cnf->sw_if_idxs[0] == ~0U)
      continue;

    vlib_cli_output(vm, "---------------------------------------");
    vlib_cli_output(vm, "If1: %U", format_vnet_sw_interface_name, vnm,
      vnet_get_sw_interface(vnm, cnf->sw_if_idxs[0]));
    vlib_cli_output(vm, "If2: %U", format_vnet_sw_interface_name, vnm,
      vnet_get_sw_interface(vnm, cnf->sw_if_idxs[1]));
    vlib_cli_output(vm, "Collector: %U", format_ip4_address, &cnf->collector);
    vlib_cli_output(vm, "Src:       %U", format_ip4_address, &cnf->src);

    t = 0;
    vec_foreach(td, fm->tdata) {
      vlib_cli_output(vm, "Thread %d table entries: %u", t++, td->table_entries);
    }
  }

  return 0;
}

/*?
 * '<em>ntflowprobe enable</em>' commands to enable/disable
 * per-packet IPFIX flow record generation on an interface
 *
 * @cliexpar
 * @parblock
 * To enable per-packet IPFIX flow-record generation on an interface:
 * @cliexcmd{ntflowprobe feature add-del GigabitEthernet2/0/0}
 *
 * To disable per-packet IPFIX flow-record generation on an interface:
 * @cliexcmd{ntflowprobe feature add-del GigabitEthernet2/0/0 disable}
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(ntflowprobe_enable_command, static) = {
    .path = "ntflowprobe enable",
    .short_help =
    "ntflowprobe enable <interface-name-1> <interface-name-2> <collector-ip>",
    .function = ntflowprobe_enable_disable_fn,
    .function_arg = 1,
};

VLIB_CLI_COMMAND(ntflowprobe_disable_command, static) = {
    .path = "ntflowprobe disable",
    .short_help =
    "ntflowprobe enable <interface-name-1> <interface-name-2>",
    .function = ntflowprobe_enable_disable_fn,
    .function_arg = 0,
};

VLIB_CLI_COMMAND(ntflowprobe_status_command, static) = {
  .path = "ntflowprobe status",
  .short_help = "ntflowprobe status",
  .function = ntflowprobe_status_fn,
  .function_arg = 0,
};
/* *INDENT-ON* */

/**
 * @brief Plugin API message handler.
 */
static void vl_api_ntflowprobe_enable_disable_t_handler
(vl_api_ntflowprobe_enable_disable_t * mp)
{
  vl_api_ntflowprobe_enable_disable_reply_t * rmp;
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  int rv;

  rv = ntflowprobe_enable_disable(fm, mp->enable, ntohl(mp->sw_if_index_1),
          ntohl(mp->sw_if_index_2), (ip4_address_t)mp->collector_ip,
          (ip4_address_t)mp->src_ip);

  REPLY_MACRO(VL_API_NTFLOWPROBE_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well
 */
static clib_error_t *
ntflowprobe_plugin_api_hookup(vlib_main_t * vm)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + fm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ntflowprobe_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ntflowprobe/ntflowprobe_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ntflowprobe_main_t * fm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + fm->msg_id_base);
  foreach_vl_msg_name_crc_ntflowprobe;
#undef _
}

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well, or a clib_error_t
 */
static clib_error_t *
ntflowprobe_init (vlib_main_t * vm)
{
  ntflowprobe_main_t *fm = &ntflowprobe_main;
  vnet_interface_main_t *im;
  clib_error_t *error = 0;
  u8 *name;
  int i;

  fm->vnet_main = vnet_get_main ();
  im = &fm->vnet_main->interface_main;

  /* Construct the API name */
  name = format (0, "ntflowprobe_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  fm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* Hook up message handlers */
  error = ntflowprobe_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table(fm, &api_main);

  vec_free(name);

  /* Set up time reference pair */
  fm->vlib_time_0 = vlib_time_now (vm);
  fm->nanosecond_time_0 = unix_time_now_nsec ();

  fm->ht_log2len = NTFLOWPROBE_LOG2_HASHBUCKETS;

  vec_validate(fm->configs, vec_len(im->hw_interfaces)/2);
  for (i = 0; i < vec_len(fm->configs); i++)
    fm->configs[i].sw_if_idxs[0] = ~0U;

  fm->initialized = 0;

  return error;
}

VLIB_INIT_FUNCTION (ntflowprobe_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
