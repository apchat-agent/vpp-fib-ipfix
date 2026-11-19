/*
 * Copyright (c) 2026 claude-helper (apchat-agent)
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
 * fibipfix: export FIB entry programming events over IPFIX.
 *
 * The core FIB calls us (fib_entry_install_notify_register) when an entry's
 * forwarding is installed (ADD), modified in place (UPDATE) or removed
 * (REMOVE). Each event is written into the open IPFIX packet at once, with
 * the entry's state at that moment. If the entry already has a record in
 * that same open packet, the record is overwritten in place and its event
 * count goes up: the coalescing window is the packet being filled. Once the
 * packet is sent (full, or on the interval timer), the next event for the
 * entry starts a new record in the next packet.
 *
 * Everything here runs on the main thread: FIB updates happen there with the
 * workers at the barrier, and the flush runs in a process node.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/ipfix_info_elements.h>
#include <vnet/udp/udp_local.h>

typedef enum
{
  FIBIPFIX_EVENT_ADD = 1,
  FIBIPFIX_EVENT_UPDATE = 2,
  FIBIPFIX_EVENT_REMOVE = 3,
  FIBIPFIX_EVENT_RESYNC = 4,
} fibipfix_event_t;

/* what one record says about an entry */
typedef struct
{
  fib_prefix_t prefix; /* normalized */
  u32 table_id;
  ip46_address_t nh; /* first path */
  u32 sw_if_index;
  u16 n_paths;
} fibipfix_state_t;

/* report_elements: the high bit of info_element marks an enterprise IE */
#define FIBIPFIX_ENTERPRISE_BIT 0x8000
#define FIBIPFIX_IE_EVENT_TYPE	(FIBIPFIX_ENTERPRISE_BIT | 1)
#define FIBIPFIX_IE_EVENT_COUNT (FIBIPFIX_ENTERPRISE_BIT | 2)
#define FIBIPFIX_IE_PATH_COUNT	(FIBIPFIX_ENTERPRISE_BIT | 3)

/* RFC 5612: enterprise number for documentation use, until a real PEN */
#define FIBIPFIX_DEFAULT_PEN 32473

#define foreach_fibipfix_ip4_element                                          \
  _ (ingressVRFID, 4)                                                         \
  _ (destinationIPv4Address, 4)                                               \
  _ (destinationIPv4PrefixLength, 1)                                          \
  _ (ipNextHopIPv4Address, 4)                                                 \
  _ (egressInterface, 4)                                                      \
  _ (observationTimeMilliseconds, 8)

#define foreach_fibipfix_ip6_element                                          \
  _ (ingressVRFID, 4)                                                         \
  _ (destinationIPv6Address, 16)                                              \
  _ (destinationIPv6PrefixLength, 1)                                          \
  _ (ipNextHopIPv6Address, 16)                                                \
  _ (egressInterface, 4)                                                      \
  _ (observationTimeMilliseconds, 8)

#define foreach_fibipfix_enterprise_element                                   \
  { FIBIPFIX_IE_EVENT_TYPE, 1 }, { FIBIPFIX_IE_EVENT_COUNT, 4 },              \
  {                                                                           \
    FIBIPFIX_IE_PATH_COUNT, 2                                                 \
  }

static ipfix_report_element_t fibipfix_ip4_elements[] = {
#define _(n, s) { n, s },
  foreach_fibipfix_ip4_element
#undef _
    foreach_fibipfix_enterprise_element
};

static ipfix_report_element_t fibipfix_ip6_elements[] = {
#define _(n, s) { n, s },
  foreach_fibipfix_ip6_element
#undef _
    foreach_fibipfix_enterprise_element
};

typedef enum
{
  FIBIPFIX_AF_IP4 = 0,
  FIBIPFIX_AF_IP6,
  FIBIPFIX_N_AF,
} fibipfix_af_t;

typedef enum
{
  FIBIPFIX_PROCESS_EVENT_FLUSH = 1,
} fibipfix_process_event_t;

typedef struct
{
  u8 enabled;

  /* config */
  f64 interval;	  /* seconds between timer sends of the open packets */
  u32 enterprise; /* PEN of the enterprise IEs */
  u32 domain_id;
  u16 src_port;

  /* per address family, for the open packet: which record slot each entry
   * has (fei -> slot), and which entry each slot belongs to (~0 = a REMOVE,
   * no longer keyed: the fib entry index can be reused) */
  uword *slot_by_fei[2];
  u32 *slot_fei[2];

  /* flow report bookkeeping */
  u16 template_id[FIBIPFIX_N_AF];
  u32 stream_index;

  /* time reference for observationTimeMilliseconds */
  f64 vlib_time_0;
  u64 unix_ms_0;

  u32 process_node_index;

  /* counters */
  u64 n_events;
  u64 n_coalesced;
  u64 n_cancelled; /* ADD then REMOVE in the same open packet */
  u64 n_records;
  u64 n_packets_sent;
  u64 n_dropped_no_collector;
  u64 n_dropped_no_buffer;
  u64 n_skipped_other_proto;
  u64 n_timer_sends;
} fibipfix_main_t;

static fibipfix_main_t fibipfix_main;

static u64
fibipfix_now_ms (vlib_main_t *vm)
{
  fibipfix_main_t *fm = &fibipfix_main;
  return fm->unix_ms_0 + (u64) ((vlib_time_now (vm) - fm->vlib_time_0) * 1e3);
}

static ipfix_exporter_t *
fibipfix_exporter (void)
{
  return pool_elt_at_index (flow_report_main.exporters, 0);
}

static int
fibipfix_have_collector (ipfix_exporter_t *exp)
{
  return !ip_address_is_zero (&exp->ipfix_collector) &&
	 !ip_address_is_zero (&exp->src_address);
}

/*
 * Template rewrite. Same as vnet_flow_rewrite_generic_callback except that it
 * writes enterprise field specifiers (that one cannot, and the header writer
 * it uses is static to flow_report.c).
 */
static u8 *
fibipfix_rewrite_callback (ipfix_exporter_t *exp, flow_report_t *fr,
			   u16 collector_port, ipfix_report_element_t *elts,
			   u32 n_elts, u32 *stream_indexp)
{
  fibipfix_main_t *fm = &fibipfix_main;
  flow_report_stream_t *stream;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ipfix_template_header_t *t;
  udp_header_t *udp;
  u8 *rewrite = 0;
  u8 *f, *first_field;
  u32 hdr_size, fields_size = 0, i;
  int is_ip4 = ip_addr_version (&exp->ipfix_collector) == AF_IP4;

  stream = &exp->streams[fr->stream_index];
  *stream_indexp = fr->stream_index;

  for (i = 0; i < n_elts; i++)
    fields_size += (elts[i].info_element & FIBIPFIX_ENTERPRISE_BIT) ?
		     sizeof (ipfix_enterprise_field_specifier_t) :
		     sizeof (ipfix_field_specifier_t);

  hdr_size = is_ip4 ? sizeof (ip4_ipfix_template_packet_t) :
		      sizeof (ip6_ipfix_template_packet_t);
  vec_validate_aligned (rewrite, hdr_size + fields_size - 1,
			CLIB_CACHE_LINE_BYTES);

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) rewrite;
      ip4->ip_version_and_header_length = 0x45;
      ip4->ttl = 254;
      ip4->protocol = IP_PROTOCOL_UDP;
      ip4->src_address.as_u32 = exp->src_address.ip.ip4.as_u32;
      ip4->dst_address.as_u32 = exp->ipfix_collector.ip.ip4.as_u32;
      udp = (udp_header_t *) (ip4 + 1);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) rewrite;
      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip6->hop_limit = 254;
      ip6->protocol = IP_PROTOCOL_UDP;
      ip6->src_address = exp->src_address.ip.ip6;
      ip6->dst_address = exp->ipfix_collector.ip.ip6;
      udp = (udp_header_t *) (ip6 + 1);
    }

  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);
  t = (ipfix_template_header_t *) (s + 1);
  first_field = f = (u8 *) (t + 1);

  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (collector_port);
  udp->length = clib_host_to_net_u16 (vec_len (rewrite) - (is_ip4 ?
							      sizeof (ip4_header_t) :
							      sizeof (ip6_header_t)));
  /* export_time and sequence number are fixed up when the template is sent */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  for (i = 0; i < n_elts; i++)
    {
      u16 id = elts[i].info_element;
      if (id & FIBIPFIX_ENTERPRISE_BIT)
	{
	  ipfix_enterprise_field_specifier_t *ef = (void *) f;
	  ef->e_id_length = ipfix_e_id_length (1, id, elts[i].size);
	  ef->enterprise = clib_host_to_net_u32 (fm->enterprise);
	  f += sizeof (*ef);
	}
      else
	{
	  ipfix_field_specifier_t *sf = (void *) f;
	  sf->e_id_length = ipfix_e_id_length (0, id, elts[i].size);
	  f += sizeof (*sf);
	}
    }

  t->id_count = ipfix_id_count (fr->template_id, n_elts);
  s->set_id_length = ipfix_set_id_length (2 /* template set */, f - (u8 *) s);
  h->version_length = version_length (f - (u8 *) h);

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) rewrite;
      ip4->length = clib_host_to_net_u16 (f - rewrite);
      ip4->checksum = ip4_header_checksum (ip4);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) rewrite;
      ip6->payload_length = clib_host_to_net_u16 (f - (u8 *) udp);
    }

  ASSERT (f - first_field == fields_size);
  return rewrite;
}

/* We send data from our own process node; the exporter's periodic call is a
 * no-op that hands back the frame (it may hold the template). */
static vlib_frame_t *
fibipfix_data_callback (flow_report_main_t *frm, ipfix_exporter_t *exp,
			flow_report_t *fr, vlib_frame_t *f, u32 *to_next,
			u32 node_index)
{
  return f;
}

static flow_report_t *
fibipfix_find_report (ipfix_exporter_t *exp, fibipfix_af_t af)
{
  flow_report_t *fr;

  /* exp->reports is a vector that shifts when other reports are deleted,
   * so look ours up instead of caching an index */
  vec_foreach (fr, exp->reports)
    {
      if (fr->rewrite_callback == fibipfix_rewrite_callback &&
	  fr->opaque.as_uword == af + 1)
	return fr;
    }
  return 0;
}

/* offsets of the event type and event count inside a record */
static const u32 fibipfix_event_offset[FIBIPFIX_N_AF] = {
  4 + 4 + 1 + 4 + 4 + 8,
  4 + 16 + 1 + 16 + 4 + 8,
};

/* the open packet of an address family is gone (sent, or freed by the
 * exporter): forget which entries had a record in it */
static void
fibipfix_packet_closed (fibipfix_af_t af)
{
  fibipfix_main_t *fm = &fibipfix_main;

  hash_free (fm->slot_by_fei[af]);
  fm->slot_by_fei[af] = hash_create (0, sizeof (uword));
  vec_reset_length (fm->slot_fei[af]);
}

static void
fibipfix_send (vlib_main_t *vm, ipfix_exporter_t *exp, flow_report_t *fr,
	       fibipfix_af_t af)
{
  fibipfix_main_t *fm = &fibipfix_main;
  flow_report_per_thread_t *ptd = &fr->per_thread_data[vm->thread_index];
  flow_report_stream_t *stream = &exp->streams[fr->stream_index];

  if (ptd->buffer && ptd->next_data_offset > exp->all_headers_size)
    {
      vnet_ipfix_exp_send_buffer (vm, exp, fr, stream, vm->thread_index,
				  ptd->buffer);
      /* send_buffer consumes n_data_records for the sequence number but
       * does not reset it */
      ptd->n_data_records = 0;
      fm->n_packets_sent++;
    }
  fibipfix_packet_closed (af);
}

/* read what a record says about the entry; -1 if it is not IP */
static int
fibipfix_read_state (fib_node_index_t fei, int with_paths,
		     fibipfix_state_t *st)
{
  /* some entries (e.g. an interface's connected prefix) keep the host
   * address with the prefix length; collectors expect the network */
  fib_prefix_normalize (fib_entry_get_prefix (fei), &st->prefix);
  st->table_id = fib_table_get_table_id (fib_entry_get_fib_index (fei),
					 st->prefix.fp_proto);
  clib_memset (&st->nh, 0, sizeof (st->nh));
  st->sw_if_index = ~0;
  st->n_paths = 0;

  if (with_paths)
    {
      fib_route_path_t *paths = fib_entry_encode (fei);

      st->n_paths = vec_len (paths);
      if (st->n_paths)
	st->nh = paths[0].frp_addr;
      vec_free (paths);
      st->sw_if_index = fib_entry_get_resolving_interface (fei);
    }

  if (st->prefix.fp_proto == FIB_PROTOCOL_IP4)
    return FIBIPFIX_AF_IP4;
  if (st->prefix.fp_proto == FIB_PROTOCOL_IP6)
    return FIBIPFIX_AF_IP6;
  return -1;
}

static void
fibipfix_write_record (u8 *d, fibipfix_af_t af, const fibipfix_state_t *st,
		       u64 ms, u8 event, u32 n_events)
{
  clib_mem_unaligned (d, u32) = clib_host_to_net_u32 (st->table_id);
  d += 4;
  if (af == FIBIPFIX_AF_IP4)
    {
      clib_memcpy_fast (d, &st->prefix.fp_addr.ip4, 4);
      d += 4;
      *d++ = st->prefix.fp_len;
      clib_memcpy_fast (d, &st->nh.ip4, 4);
      d += 4;
    }
  else
    {
      clib_memcpy_fast (d, &st->prefix.fp_addr.ip6, 16);
      d += 16;
      *d++ = st->prefix.fp_len;
      clib_memcpy_fast (d, &st->nh.ip6, 16);
      d += 16;
    }
  clib_mem_unaligned (d, u32) = clib_host_to_net_u32 (st->sw_if_index);
  d += 4;
  clib_mem_unaligned (d, u64) = clib_host_to_net_u64 (ms);
  d += 8;
  *d++ = event;
  clib_mem_unaligned (d, u32) = clib_host_to_net_u32 (n_events);
  d += 4;
  clib_mem_unaligned (d, u16) = clib_host_to_net_u16 (st->n_paths);
}

/* take a record out of the open packet: the last record moves into its slot */
static void
fibipfix_slot_delete (ipfix_exporter_t *exp, flow_report_t *fr,
		      flow_report_per_thread_t *ptd, fibipfix_af_t af,
		      u32 slot)
{
  fibipfix_main_t *fm = &fibipfix_main;
  u32 rs = fr->data_record_size;
  u32 last = vec_len (fm->slot_fei[af]) - 1;
  u8 *base = (u8 *) vlib_buffer_get_current (ptd->buffer) +
	     exp->all_headers_size;

  if (slot != last)
    {
      u32 moved = fm->slot_fei[af][last];

      clib_memcpy_fast (base + slot * rs, base + last * rs, rs);
      fm->slot_fei[af][slot] = moved;
      if (moved != ~0)
	hash_set (fm->slot_by_fei[af], moved, slot);
    }
  vec_set_len (fm->slot_fei[af], last);
  ptd->buffer->current_length -= rs;
  ptd->next_data_offset -= rs;
  ptd->n_data_records--;
  fm->n_cancelled++;
}

static void
fibipfix_event (vlib_main_t *vm, fib_node_index_t fei, u8 event)
{
  fibipfix_main_t *fm = &fibipfix_main;
  ipfix_exporter_t *exp = fibipfix_exporter ();
  flow_report_per_thread_t *ptd;
  fibipfix_state_t st;
  flow_report_t *fr;
  vlib_buffer_t *b;
  u32 rs, slot, n_events;
  u8 *d, old_event;
  uword *p;
  u64 now;
  int af;

  if (!fibipfix_have_collector (exp))
    {
      fm->n_dropped_no_collector++;
      return;
    }

  /* a REMOVE has no paths any more; the prefix is still readable */
  af = fibipfix_read_state (fei, event != FIBIPFIX_EVENT_REMOVE, &st);
  if (af < 0)
    {
      fm->n_skipped_other_proto++;
      return;
    }

  fr = fibipfix_find_report (exp, af);
  if (!fr)
    return;
  ptd = &fr->per_thread_data[vm->thread_index];
  rs = fr->data_record_size;
  now = fibipfix_now_ms (vm);

  /* the exporter may have freed our open packet (reconfiguration) */
  if (!ptd->buffer && vec_len (fm->slot_fei[af]))
    fibipfix_packet_closed (af);

  p = hash_get (fm->slot_by_fei[af], fei);
  if (p)
    {
      /* the entry has a record in the open packet: overwrite it */
      slot = p[0];
      d = (u8 *) vlib_buffer_get_current (ptd->buffer) +
	  exp->all_headers_size + slot * rs;
      old_event = d[fibipfix_event_offset[af]];
      n_events = clib_net_to_host_u32 (
		   clib_mem_unaligned (d + fibipfix_event_offset[af] + 1, u32)) +
		 1;
      fm->n_coalesced++;

      switch (event)
	{
	case FIBIPFIX_EVENT_REMOVE:
	  hash_unset (fm->slot_by_fei[af], fei);
	  fm->slot_fei[af][slot] = ~0;
	  if (old_event == FIBIPFIX_EVENT_ADD)
	    {
	      /* the collector never saw it: send nothing */
	      fibipfix_slot_delete (exp, fr, ptd, af, slot);
	      return;
	    }
	  break;
	case FIBIPFIX_EVENT_UPDATE:
	  /* the collector has not seen the ADD yet */
	  if (old_event == FIBIPFIX_EVENT_ADD)
	    event = FIBIPFIX_EVENT_ADD;
	  break;
	case FIBIPFIX_EVENT_RESYNC:
	  /* already in this packet with its latest state */
	  fm->n_coalesced--;
	  return;
	default:
	  break;
	}
      fibipfix_write_record (d, af, &st, now, event, n_events);
      return;
    }

  /* a new record: make room first (MTU; n_data_records is a u8) */
  if (ptd->buffer && (ptd->next_data_offset + rs > exp->path_mtu ||
		      ptd->n_data_records == 255))
    fibipfix_send (vm, exp, fr, af);

  b = vnet_ipfix_exp_get_buffer (vm, exp, fr, vm->thread_index);
  if (!b)
    {
      fm->n_dropped_no_buffer++;
      return;
    }

  slot = vec_len (fm->slot_fei[af]);
  ASSERT (ptd->next_data_offset == exp->all_headers_size + slot * rs);
  d = (u8 *) vlib_buffer_get_current (b) + ptd->next_data_offset;
  fibipfix_write_record (d, af, &st, now, event, 1);
  b->current_length += rs;
  ptd->next_data_offset += rs;
  ptd->n_data_records++;
  fm->n_records++;

  if (event == FIBIPFIX_EVENT_REMOVE)
    vec_add1 (fm->slot_fei[af], ~0);
  else
    {
      vec_add1 (fm->slot_fei[af], fei);
      hash_set (fm->slot_by_fei[af], fei, slot);
    }
}

/* send whatever is in the open packets */
static void
fibipfix_flush (vlib_main_t *vm)
{
  ipfix_exporter_t *exp = fibipfix_exporter ();
  flow_report_t *fr;
  u32 af;

  for (af = 0; af < FIBIPFIX_N_AF; af++)
    {
      fr = fibipfix_find_report (exp, af);
      if (fr)
	fibipfix_send (vm, exp, fr, af);
      else
	fibipfix_packet_closed (af);
    }
}

/* fib_entry_install_notify_fn_t */
static void
fibipfix_install_notify (fib_node_index_t fei, fib_entry_install_event_t ev)
{
  fibipfix_main_t *fm = &fibipfix_main;
  static const u8 map[] = {
    [FIB_ENTRY_INSTALL_EVENT_ADD] = FIBIPFIX_EVENT_ADD,
    [FIB_ENTRY_INSTALL_EVENT_UPDATE] = FIBIPFIX_EVENT_UPDATE,
    [FIB_ENTRY_INSTALL_EVENT_REMOVE] = FIBIPFIX_EVENT_REMOVE,
  };

  fm->n_events++;
  fibipfix_event (vlib_get_main (), fei, map[ev]);
}

static fib_table_walk_rc_t
fibipfix_resync_walk (fib_node_index_t fei, void *ctx)
{
  /* only entries that are programmed */
  if (dpo_id_is_valid (&fib_entry_get (fei)->fe_lb))
    fibipfix_event (ctx, fei, FIBIPFIX_EVENT_RESYNC);
  return FIB_TABLE_WALK_CONTINUE;
}

static void
fibipfix_resync (vlib_main_t *vm)
{
  fib_table_t *fib_table;

  pool_foreach (fib_table, ip4_main.fibs)
    fib_table_walk (fib_table->ft_index, FIB_PROTOCOL_IP4,
		    fibipfix_resync_walk, vm);
  pool_foreach (fib_table, ip6_main.fibs)
    fib_table_walk (fib_table->ft_index, FIB_PROTOCOL_IP6,
		    fibipfix_resync_walk, vm);
}

static uword
fibipfix_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  fibipfix_main_t *fm = &fibipfix_main;
  uword *event_data = 0;

  while (1)
    {
      if (fm->enabled)
	vlib_process_wait_for_event_or_clock (vm, fm->interval);
      else
	vlib_process_wait_for_event (vm);

      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      if (fm->enabled)
	{
	  fm->n_timer_sends++;
	  fibipfix_flush (vm);
	}
    }
  return 0;
}

VLIB_REGISTER_NODE (fibipfix_process_node) = {
  .function = fibipfix_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "fibipfix-process",
};

static int
fibipfix_report_add_del (fibipfix_af_t af, int is_add)
{
  fibipfix_main_t *fm = &fibipfix_main;
  vnet_flow_report_add_del_args_t a = {
    .rewrite_callback = fibipfix_rewrite_callback,
    .flow_data_callback = fibipfix_data_callback,
    .report_elements =
      af == FIBIPFIX_AF_IP4 ? fibipfix_ip4_elements : fibipfix_ip6_elements,
    .n_report_elements = af == FIBIPFIX_AF_IP4 ?
			   ARRAY_LEN (fibipfix_ip4_elements) :
			   ARRAY_LEN (fibipfix_ip6_elements),
    .opaque.as_uword = af + 1,
    .is_add = is_add,
    .domain_id = fm->domain_id,
    .src_port = fm->src_port,
    .stream_indexp = &fm->stream_index,
  };

  return vnet_flow_report_add_del (fibipfix_exporter (), &a,
				   &fm->template_id[af]);
}

static void
fibipfix_free_state (void)
{
  fibipfix_main_t *fm = &fibipfix_main;
  u32 af;

  for (af = 0; af < FIBIPFIX_N_AF; af++)
    {
      hash_free (fm->slot_by_fei[af]);
      vec_free (fm->slot_fei[af]);
    }
}

static clib_error_t *
fibipfix_enable_disable (vlib_main_t *vm, int enable)
{
  fibipfix_main_t *fm = &fibipfix_main;
  fibipfix_af_t af;
  int rv;

  if (enable == fm->enabled)
    return 0;

  if (enable)
    {
      for (af = 0; af < FIBIPFIX_N_AF; af++)
	{
	  rv = fibipfix_report_add_del (af, 1);
	  if (rv)
	    {
	      while (af-- > 0)
		fibipfix_report_add_del (af, 0);
	      return flow_report_add_del_error_to_clib_error (rv);
	    }
	}
      for (af = 0; af < FIBIPFIX_N_AF; af++)
	fm->slot_by_fei[af] = hash_create (0, sizeof (uword));
      fm->vlib_time_0 = vlib_time_now (vm);
      fm->unix_ms_0 = unix_time_now_nsec () / 1000000;
      fib_entry_install_notify_register (fibipfix_install_notify);
      fm->enabled = 1;
      /* wake the process so it starts its timer */
      vlib_process_signal_event (vm, fm->process_node_index,
				 FIBIPFIX_PROCESS_EVENT_FLUSH, 0);
    }
  else
    {
      fib_entry_install_notify_unregister (fibipfix_install_notify);
      fibipfix_flush (vm);
      for (af = 0; af < FIBIPFIX_N_AF; af++)
	fibipfix_report_add_del (af, 0);
      fibipfix_free_state ();
      fm->enabled = 0;
    }
  return 0;
}

static clib_error_t *
fibipfix_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  fibipfix_main_t *fm = &fibipfix_main;
  u32 interval_ms = ~0, pen = ~0, domain = ~0, port = ~0;
  int disable = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	disable = 1;
      else if (unformat (input, "interval %u", &interval_ms))
	;
      else if (unformat (input, "enterprise %u", &pen))
	;
      else if (unformat (input, "domain %u", &domain))
	;
      else if (unformat (input, "src-port %u", &port))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (disable)
    return fibipfix_enable_disable (vm, 0);

  if (fm->enabled && (pen != ~0 || domain != ~0 || port != ~0))
    return clib_error_return (
      0, "disable first to change enterprise, domain or src-port");

  if (interval_ms != ~0)
    {
      if (interval_ms == 0)
	return clib_error_return (0, "interval must be > 0 ms");
      fm->interval = interval_ms * 1e-3;
    }
  if (pen != ~0)
    fm->enterprise = pen;
  if (domain != ~0)
    fm->domain_id = domain;
  if (port != ~0)
    {
      if (port > 65535)
	return clib_error_return (0, "src-port out of range");
      fm->src_port = port;
    }

  return fibipfix_enable_disable (vm, 1);
}

/*?
 * Export FIB entry install/update/remove events to the IPFIX collector set
 * with 'set ipfix exporter'. Events on an entry that already has a record in
 * the open packet overwrite that record; the open packet is sent when full
 * or every interval.
 *
 * @cliexpar
 * @cliexcmd{fib ipfix enable interval 100}
 * @cliexcmd{fib ipfix enable disable}
?*/
VLIB_CLI_COMMAND (fibipfix_enable_command, static) = {
  .path = "fib ipfix enable",
  .short_help = "fib ipfix enable [interval <ms>] "
		"[enterprise <pen>] [domain <id>] [src-port <port>] [disable]",
  .function = fibipfix_enable_command_fn,
};

static clib_error_t *
fibipfix_resync_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  if (!fibipfix_main.enabled)
    return clib_error_return (0, "fib ipfix is not enabled");
  fibipfix_resync (vm);
  return 0;
}

VLIB_CLI_COMMAND (fibipfix_resync_command, static) = {
  .path = "fib ipfix resync",
  .short_help = "fib ipfix resync",
  .function = fibipfix_resync_command_fn,
};

static clib_error_t *
fibipfix_flush_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  if (!fibipfix_main.enabled)
    return clib_error_return (0, "fib ipfix is not enabled");
  fibipfix_flush (vm);
  return 0;
}

VLIB_CLI_COMMAND (fibipfix_flush_command, static) = {
  .path = "fib ipfix flush",
  .short_help = "fib ipfix flush",
  .function = fibipfix_flush_command_fn,
};

static clib_error_t *
fibipfix_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  fibipfix_main_t *fm = &fibipfix_main;
  ipfix_exporter_t *exp = fibipfix_exporter ();

  vlib_cli_output (vm, "fib ipfix: %s", fm->enabled ? "enabled" : "disabled");
  vlib_cli_output (vm,
		   "  interval %.0f ms, enterprise %u, "
		   "domain %u, src-port %u",
		   fm->interval * 1e3, fm->enterprise,
		   fm->domain_id, fm->src_port);
  vlib_cli_output (vm, "  collector: %U -> %U%s", format_ip_address,
		   &exp->src_address, format_ip_address, &exp->ipfix_collector,
		   fibipfix_have_collector (exp) ? "" : " (not configured)");
  if (fm->enabled)
    vlib_cli_output (vm, "  template ids: ip4 %u, ip6 %u",
		     fm->template_id[FIBIPFIX_AF_IP4],
		     fm->template_id[FIBIPFIX_AF_IP6]);
  vlib_cli_output (vm, "  open packets: ip4 %u records, ip6 %u records",
		   vec_len (fm->slot_fei[FIBIPFIX_AF_IP4]),
		   vec_len (fm->slot_fei[FIBIPFIX_AF_IP6]));
  vlib_cli_output (vm,
		   "  events %llu, coalesced %llu, cancelled %llu, "
		   "timer sends %llu",
		   fm->n_events, fm->n_coalesced, fm->n_cancelled,
		   fm->n_timer_sends);
  vlib_cli_output (vm, "  records written %llu, packets sent %llu",
		   fm->n_records, fm->n_packets_sent);
  vlib_cli_output (vm,
		   "  dropped: no collector %llu, no buffer %llu, "
		   "not ip %llu",
		   fm->n_dropped_no_collector, fm->n_dropped_no_buffer,
		   fm->n_skipped_other_proto);
  return 0;
}

VLIB_CLI_COMMAND (fibipfix_show_command, static) = {
  .path = "show fib ipfix",
  .short_help = "show fib ipfix",
  .function = fibipfix_show_command_fn,
};

static clib_error_t *
fibipfix_init (vlib_main_t *vm)
{
  fibipfix_main_t *fm = &fibipfix_main;

  fm->interval = 0.1;
  fm->enterprise = FIBIPFIX_DEFAULT_PEN;
  fm->domain_id = 0x46494258; /* "FIBX" */
  fm->src_port = UDP_DST_PORT_ipfix;
  fm->process_node_index = fibipfix_process_node.index;
  return 0;
}

VLIB_INIT_FUNCTION (fibipfix_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Export FIB entry programming events over IPFIX",
};
