/* GSM Channel allocation routines
 *
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>

static int ts_is_usable(struct gsm_bts_trx_ts *ts)
{
	/* FIXME: How does this behave for BS-11 ? */
	if (is_ipaccess_bts(ts->trx->bts)) {
		if (!nm_is_running(&ts->nm_state))
			return 0;
	}

	return 1;
}

int trx_is_usable(struct gsm_bts_trx *trx)
{
	/* FIXME: How does this behave for BS-11 ? */
	if (is_ipaccess_bts(trx->bts)) {
		if (!nm_is_running(&trx->nm_state) ||
		    !nm_is_running(&trx->bb_transc.nm_state))
			return 0;
	}

	return 1;
}

struct gsm_bts_trx_ts *ts_c0_alloc(struct gsm_bts *bts,
				   enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx = bts->c0;
	struct gsm_bts_trx_ts *ts = &trx->ts[0];

	if (pchan != GSM_PCHAN_CCCH &&
	    pchan != GSM_PCHAN_CCCH_SDCCH4)
		return NULL;

	if (ts->pchan != GSM_PCHAN_NONE)
		return NULL;

	ts->pchan = pchan;

	return ts;
}

/* Allocate a physical channel (TS) */
struct gsm_bts_trx_ts *ts_alloc(struct gsm_bts *bts,
				enum gsm_phys_chan_config pchan)
{
	int j;
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int from, to;

		if (!trx_is_usable(trx))
			continue;

		/* the following constraints are pure policy,
		 * no requirement to put this restriction in place */
		if (trx == bts->c0) {
			/* On the first TRX we run one CCCH and one SDCCH8 */
			switch (pchan) {
			case GSM_PCHAN_CCCH:
			case GSM_PCHAN_CCCH_SDCCH4:
				from = 0; to = 0;
				break;
			case GSM_PCHAN_TCH_F:
			case GSM_PCHAN_TCH_H:
				from = 1; to = 7;
				break;
			case GSM_PCHAN_SDCCH8_SACCH8C:
			default:
				return NULL;
			}
		} else {
			/* Every secondary TRX is configured for TCH/F
			 * and TCH/H only */
			switch (pchan) {
			case GSM_PCHAN_SDCCH8_SACCH8C:
				from = 1; to = 1;
			case GSM_PCHAN_TCH_F:
			case GSM_PCHAN_TCH_H:
				from = 1; to = 7;
				break;
			default:
				return NULL;
			}
		}

		for (j = from; j <= to; j++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[j];

			if (!ts_is_usable(ts))
				continue;

			if (ts->pchan == GSM_PCHAN_NONE) {
				ts->pchan = pchan;
				/* set channel attribute on OML */
				abis_nm_set_channel_attr(ts, abis_nm_chcomb4pchan(pchan));
				return ts;
			}
		}
	}
	return NULL;
}

/* Free a physical channel (TS) */
void ts_free(struct gsm_bts_trx_ts *ts)
{
	ts->pchan = GSM_PCHAN_NONE;
}

static const u_int8_t subslots_per_pchan[] = {
	[GSM_PCHAN_NONE] = 0,
	[GSM_PCHAN_CCCH] = 0,
	[GSM_PCHAN_CCCH_SDCCH4] = 4,
	[GSM_PCHAN_TCH_F] = 1,
	[GSM_PCHAN_TCH_H] = 2,
	[GSM_PCHAN_SDCCH8_SACCH8C] = 8,
	/* FIXME: what about dynamic TCH_F_TCH_H ? */
};

static struct gsm_lchan *
_lc_find_trx(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx_ts *ts;
	int j, ss;

	if (!trx_is_usable(trx))
		return NULL;

	for (j = 0; j < 8; j++) {
		ts = &trx->ts[j];
		if (!ts_is_usable(ts))
			continue;
		if (ts->pchan != pchan)
			continue;
		/* check if all sub-slots are allocated yet */
		for (ss = 0; ss < subslots_per_pchan[pchan]; ss++) {
			struct gsm_lchan *lc = &ts->lchan[ss];
			if (lc->type == GSM_LCHAN_NONE &&
			    lc->state == LCHAN_S_NONE)
				return lc;
		}
	}
	return NULL;
}

static struct gsm_lchan *
_lc_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lc;

	if (bts->chan_alloc_reverse) {
		llist_for_each_entry_reverse(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan);
			if (lc)
				return lc;
		}
	} else {
		llist_for_each_entry(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan);
			if (lc)
				return lc;
		}
	}

	/* we cannot allocate more of these */
	if (pchan == GSM_PCHAN_CCCH_SDCCH4)
		return NULL;

	/* if we've reached here, we need to allocate a new physical
	 * channel for the logical channel type requested */
	ts = ts_alloc(bts, pchan);
	if (!ts) {
		/* no more radio resources */
		return NULL;
	}
	return &ts->lchan[0];
}

/* Allocate a logical channel */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type)
{
	struct gsm_lchan *lchan = NULL;
	enum gsm_phys_chan_config first, second;

	switch (type) {
	case GSM_LCHAN_SDCCH:
		if (bts->chan_alloc_reverse) {
			first = GSM_PCHAN_SDCCH8_SACCH8C;
			second = GSM_PCHAN_CCCH_SDCCH4;
		} else {
			first = GSM_PCHAN_CCCH_SDCCH4;
			second = GSM_PCHAN_SDCCH8_SACCH8C;
		}

		lchan = _lc_find_bts(bts, first);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second);
		break;
	case GSM_LCHAN_TCH_F:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
		break;
	case GSM_LCHAN_TCH_H:
		lchan =_lc_find_bts(bts, GSM_PCHAN_TCH_H);
		/* If we don't have TCH/H available, fall-back to TCH/F */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
			type = GSM_LCHAN_TCH_F;
		}
		break;
	default:
		LOGP(DRLL, LOGL_ERROR, "Unknown gsm_chan_t %u\n", type);
	}

	if (lchan) {
		lchan->type = type;
		lchan->use_count = 0;

		/* clear sapis */
		memset(lchan->sapis, 0, ARRAY_SIZE(lchan->sapis));

		/* clear multi rate config */
		memset(&lchan->mr_conf, 0, sizeof(lchan->mr_conf));

		/* clear any msc reference */
		lchan->msc_data = NULL;

	}

	return lchan;
}

/* Free a logical channel */
void lchan_free(struct gsm_lchan *lchan)
{
	int i;

	lchan->type = GSM_LCHAN_NONE;
	if (lchan->subscr) {
		subscr_put(lchan->subscr);
		lchan->subscr = NULL;
	}

	/* We might kill an active channel... */
	if (lchan->use_count != 0) {
		dispatch_signal(SS_LCHAN, S_LCHAN_UNEXPECTED_RELEASE, lchan);
		lchan->use_count = 0;
	}

	bsc_del_timer(&lchan->T3101);

	/* clear cached measuement reports */
	lchan->meas_rep_idx = 0;
	for (i = 0; i < ARRAY_SIZE(lchan->meas_rep); i++) {
		lchan->meas_rep[i].flags = 0;
		lchan->meas_rep[i].nr = 0;
	}
	for (i = 0; i < ARRAY_SIZE(lchan->neigh_meas); i++)
		lchan->neigh_meas[i].arfcn = 0;
	lchan->silent_call = 0;

	/* FIXME: ts_free() the timeslot, if we're the last logical
	 * channel using it */
}

/* Consider releasing the channel now */
int _lchan_release(struct gsm_lchan *lchan)
{
	if (lchan->use_count > 0) {
		DEBUGP(DRLL, "BUG: _lchan_release called without zero use_count.\n");
		return 0;
	}

	/* Assume we have GSM04.08 running and send a release */
	if (lchan->subscr) {
		++lchan->use_count;
		gsm48_send_rr_release(lchan);
		--lchan->use_count;
	}

	/* spoofed? message */
	if (lchan->use_count < 0)
		LOGP(DRLL, LOGL_ERROR, "Channel count is negative: %d\n",
			lchan->use_count);

	DEBUGP(DRLL, "%s Recycling Channel\n", gsm_lchan_name(lchan));
	rsl_release_request(lchan, 0);
	return 1;
}

struct gsm_lchan* lchan_find(struct gsm_bts *bts, struct gsm_subscriber *subscr) {
	struct gsm_bts_trx *trx;
	int ts_no, lchan_no; 

	llist_for_each_entry(trx, &bts->trx_list, list) {
		for (ts_no = 0; ts_no < 8; ++ts_no) {
			for (lchan_no = 0; lchan_no < TS_MAX_LCHAN; ++lchan_no) {
				struct gsm_lchan *lchan =
					&trx->ts[ts_no].lchan[lchan_no];
				if (subscr == lchan->subscr)
					return lchan;
			}
		}
	}

	return NULL;
}

struct gsm_lchan *lchan_for_subscr(struct gsm_subscriber *subscr)
{
	struct gsm_bts *bts;
	struct gsm_network *net = subscr->net;
	struct gsm_lchan *lchan;

	llist_for_each_entry(bts, &net->bts_list, list) {
		lchan = lchan_find(bts, subscr);
		if (lchan)
			return lchan;
	}

	return NULL;
}

void bts_chan_load(struct pchan_load *cl, const struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;

		/* skip administratively deactivated tranxsceivers */
		if (!nm_is_running(&trx->nm_state) ||
		    !nm_is_running(&trx->bb_transc.nm_state))
			continue;

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct load_counter *pl = &cl->pchan[ts->pchan];
			int j;

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->nm_state))
				continue;

			for (j = 0; j < subslots_per_pchan[ts->pchan]; j++) {
				struct gsm_lchan *lchan = &ts->lchan[j];

				pl->total++;

				switch (lchan->state) {
				case LCHAN_S_NONE:
					break;
				default:
					pl->used++;
					break;
				}
			}
		}
	}
}

void network_chan_load(struct pchan_load *pl, struct gsm_network *net)
{
	struct gsm_bts *bts;

	memset(pl, 0, sizeof(*pl));

	llist_for_each_entry(bts, &net->bts_list, list)
		bts_chan_load(pl, bts);
}
