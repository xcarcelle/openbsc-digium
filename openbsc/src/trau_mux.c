/* Simple TRAU frame reflector to route voice calls */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <openbsc/gsm_data.h>
#include <openbsc/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/debug.h>
#include <openbsc/talloc.h>

u_int8_t gsm_fr_map[] = {
	6, 6, 5, 5, 4, 4, 3, 3,
	7, 2, 2, 6, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 7, 2, 2, 6, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 7, 2, 2, 6, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 7, 2, 2, 6, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3
};

struct map_entry {
	struct llist_head list;
	struct gsm_e1_subslot src, dst;
};

struct upqueue_entry {
	struct llist_head list;
	struct gsm_network *net;
	struct gsm_e1_subslot src;
	u_int32_t callref;
};

static LLIST_HEAD(ss_map);
static LLIST_HEAD(ss_upqueue);

void *tall_map_ctx, *tall_upq_ctx;

/* map one particular subslot to another subslot */
int trau_mux_map(const struct gsm_e1_subslot *src,
		 const struct gsm_e1_subslot *dst)
{
	struct map_entry *me;

	me = talloc(tall_map_ctx, struct map_entry);
	if (!me) {
		LOGP(DMIB, LOGL_FATAL, "Out of memory\n");
		return -ENOMEM;
	}

	DEBUGP(DCC, "Setting up TRAU mux map between (e1=%u,ts=%u,ss=%u) "
		"and (e1=%u,ts=%u,ss=%u)\n",
		src->e1_nr, src->e1_ts, src->e1_ts_ss,
		dst->e1_nr, dst->e1_ts, dst->e1_ts_ss);

	/* make sure to get rid of any stale old mappings */
	trau_mux_unmap(src, 0);
	trau_mux_unmap(dst, 0);

	memcpy(&me->src, src, sizeof(me->src));
	memcpy(&me->dst, dst, sizeof(me->dst));
	llist_add(&me->list, &ss_map);

	return 0;
}

int trau_mux_map_lchan(const struct gsm_lchan *src,	
			const struct gsm_lchan *dst)
{
	struct gsm_e1_subslot *src_ss, *dst_ss;

	src_ss = &src->ts->e1_link;
	dst_ss = &dst->ts->e1_link;

	return trau_mux_map(src_ss, dst_ss);
}


/* unmap one particular subslot from another subslot */
int trau_mux_unmap(const struct gsm_e1_subslot *ss, u_int32_t callref)
{
	struct map_entry *me, *me2;
	struct upqueue_entry *ue, *ue2;

	if (ss)
		llist_for_each_entry_safe(me, me2, &ss_map, list) {
			if (!memcmp(&me->src, ss, sizeof(*ss)) ||
			    !memcmp(&me->dst, ss, sizeof(*ss))) {
				llist_del(&me->list);
				return 0;
			}
		}
	llist_for_each_entry_safe(ue, ue2, &ss_upqueue, list) {
		if (ue->callref == callref) {
			llist_del(&ue->list);
			return 0;
		}
		if (ss && !memcmp(&ue->src, ss, sizeof(*ss))) {
			llist_del(&ue->list);
			return 0;
		}
	}
	return -ENOENT;
}

/* look-up an enty in the TRAU mux map */
static struct gsm_e1_subslot *
lookup_trau_mux_map(const struct gsm_e1_subslot *src)
{
	struct map_entry *me;

	llist_for_each_entry(me, &ss_map, list) {
		if (!memcmp(&me->src, src, sizeof(*src)))
			return &me->dst;
		if (!memcmp(&me->dst, src, sizeof(*src)))
			return &me->src;
	}
	return NULL;
}

/* look-up an enty in the TRAU upqueue */
struct upqueue_entry *
lookup_trau_upqueue(const struct gsm_e1_subslot *src)
{
	struct upqueue_entry *ue;

	llist_for_each_entry(ue, &ss_upqueue, list) {
		if (!memcmp(&ue->src, src, sizeof(*src)))
			return ue;
	}
	return NULL;
}

static const u_int8_t c_bits_check[] = { 0, 0, 0, 1, 0 };

/* we get called by subchan_demux */
int trau_mux_input(struct gsm_e1_subslot *src_e1_ss,
		   const u_int8_t *trau_bits, int num_bits)
{
	struct decoded_trau_frame tf;
	u_int8_t trau_bits_out[TRAU_FRAME_BITS];
	struct gsm_e1_subslot *dst_e1_ss = lookup_trau_mux_map(src_e1_ss);
	struct subch_mux *mx;
	struct upqueue_entry *ue;
	int rc;

	/* decode TRAU, change it to downlink, re-encode */
	rc = decode_trau_frame(&tf, trau_bits);
	if (rc)
		return rc;

	if (!dst_e1_ss) {
		struct msgb *msg;
		struct gsm_data_frame *frame;
		unsigned char *data;
		int i, j, k, l, o;
		/* frame shall be sent to upqueue */
		if (!(ue = lookup_trau_upqueue(src_e1_ss)))
			return -EINVAL;
		if (!ue->callref)
			return -EINVAL;
		if (memcmp(tf.c_bits, c_bits_check, sizeof(c_bits_check)))
			DEBUGPC(DMUX, "illegal trau (C1-C5) %s\n",
				hexdump(tf.c_bits, sizeof(c_bits_check)));
		msg = msgb_alloc(sizeof(struct gsm_data_frame) + 33,
				 "GSM-DATA");
		if (!msg)
			return -ENOMEM;

		frame = (struct gsm_data_frame *)msg->data;
		memset(frame, 0, sizeof(struct gsm_data_frame));
		data = frame->data;
		data[0] = 0xd << 4;
		/* reassemble d-bits */
		i = 0; /* counts bits */
		j = 4; /* counts output bits */
		k = gsm_fr_map[0]-1; /* current number bit in element */
		l = 0; /* counts element bits */
		o = 0; /* offset input bits */
		while (i < 260) {
			data[j/8] |= (tf.d_bits[k+o] << (7-(j%8)));
			if (--k < 0) {
				o += gsm_fr_map[l];
				k = gsm_fr_map[++l]-1;
			}
			i++;
			j++;
		}
		frame->msg_type = GSM_TCHF_FRAME;
		frame->callref = ue->callref;
		msgb_enqueue(&ue->net->upqueue, msg);

		return 0;
	}

	mx = e1inp_get_mux(dst_e1_ss->e1_nr, dst_e1_ss->e1_ts);
	if (!mx)
		return -EINVAL;

	trau_frame_up2down(&tf);
	encode_trau_frame(trau_bits_out, &tf);

	/* and send it to the muxer */
	return subchan_mux_enqueue(mx, dst_e1_ss->e1_ts_ss, trau_bits_out,
				   TRAU_FRAME_BITS);
}

/* add receiver instance for lchan and callref */
int trau_recv_lchan(struct gsm_lchan *lchan, u_int32_t callref)
{
	struct gsm_e1_subslot *src_ss;
	struct upqueue_entry *ue;

	ue = talloc(tall_upq_ctx, struct upqueue_entry);
	if (!ue)
		return -ENOMEM;

	src_ss = &lchan->ts->e1_link;

	DEBUGP(DCC, "Setting up TRAU receiver (e1=%u,ts=%u,ss=%u) "
		"and (callref 0x%x)\n",
		src_ss->e1_nr, src_ss->e1_ts, src_ss->e1_ts_ss,
		callref);

	/* make sure to get rid of any stale old mappings */
	trau_mux_unmap(src_ss, callref);

	memcpy(&ue->src, src_ss, sizeof(ue->src));
	ue->net = lchan->ts->trx->bts->network;
	ue->callref = callref;
	llist_add(&ue->list, &ss_upqueue);

	return 0;
}

int trau_send_frame(struct gsm_lchan *lchan, struct gsm_data_frame *frame)
{
	u_int8_t trau_bits_out[TRAU_FRAME_BITS];
	struct gsm_e1_subslot *dst_e1_ss = &lchan->ts->e1_link;
	struct subch_mux *mx;
	int i, j, k, l, o;
	unsigned char *data = frame->data;
	struct decoded_trau_frame tf;

	mx = e1inp_get_mux(dst_e1_ss->e1_nr, dst_e1_ss->e1_ts);
	if (!mx)
		return -EINVAL;

	switch (frame->msg_type) {
	case GSM_TCHF_FRAME:
		/* set c-bits and t-bits */
		tf.c_bits[0] = 1;
		tf.c_bits[1] = 1;
		tf.c_bits[2] = 1;
		tf.c_bits[3] = 0;
		tf.c_bits[4] = 0;
		memset(&tf.c_bits[5], 0, 6);
		memset(&tf.c_bits[11], 1, 10);
		memset(&tf.t_bits[0], 1, 4);
		/* reassemble d-bits */
		i = 0; /* counts bits */
		j = 4; /* counts input bits */
		k = gsm_fr_map[0]-1; /* current number bit in element */
		l = 0; /* counts element bits */
		o = 0; /* offset output bits */
		while (i < 260) {
			tf.d_bits[k+o] = (data[j/8] >> (7-(j%8))) & 1;
			if (--k < 0) {
				o += gsm_fr_map[l];
				k = gsm_fr_map[++l]-1;
			}
			i++;
			j++;
		}
		break;
	default:
		DEBUGPC(DMUX, "unsupported message type %d\n",
			frame->msg_type);
		return -EINVAL;
	}

	encode_trau_frame(trau_bits_out, &tf);

	/* and send it to the muxer */
	return subchan_mux_enqueue(mx, dst_e1_ss->e1_ts_ss, trau_bits_out,
				   TRAU_FRAME_BITS);
}
