/* GSM BSC Radio Link Layer API
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>

#include <openbsc/debug.h>
#include <openbsc/talloc.h>
#include <openbsc/timer.h>
#include <openbsc/linuxlist.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/abis_rsl.h>

struct bsc_rll_req {
	struct llist_head list;
	struct timer_list timer;

	struct gsm_lchan *lchan;
	u_int8_t link_id;

	void (*cb)(struct gsm_lchan *lchan, u_int8_t link_id,
		   void *data, enum bsc_rllr_ind);
	void *data;
};

/* we only compare C1, C2 and SAPI */
#define LINKID_MASK	0xC7

static LLIST_HEAD(bsc_rll_reqs);

static void complete_rllr(struct bsc_rll_req *rllr, enum bsc_rllr_ind type)
{
	llist_del(&rllr->list);
	put_lchan(rllr->lchan);
	rllr->cb(rllr->lchan, rllr->link_id, rllr->data, type);
	talloc_free(rllr);
}

static void timer_cb(void *_rllr)
{
	struct bsc_rll_req *rllr = _rllr;

	complete_rllr(rllr, BSC_RLLR_IND_TIMEOUT);
}

/* establish a RLL connection with given SAPI / priority */
int rll_establish(struct gsm_lchan *lchan, u_int8_t sapi,
		  void (*cb)(struct gsm_lchan *, u_int8_t, void *,
			     enum bsc_rllr_ind),
		  void *data)
{
	struct bsc_rll_req *rllr = talloc_zero(tall_bsc_ctx, struct bsc_rll_req);
	u_int8_t link_id;
	if (!rllr)
		return -ENOMEM;

	link_id = sapi;

	/* If we are a TCH and not in signalling mode, we need to
	 * indicate that the new RLL connection is to be made on the SACCH */
	if ((lchan->type == GSM_LCHAN_TCH_F ||
	     lchan->type == GSM_LCHAN_TCH_H) &&
	    lchan->rsl_cmode != RSL_CMOD_SPD_SIGN)
		link_id |= 0x40;

	use_lchan(lchan);
	rllr->lchan = lchan;
	rllr->link_id = link_id;
	rllr->cb = cb;
	rllr->data = data;

	llist_add(&rllr->list, &bsc_rll_reqs);

	rllr->timer.cb = &timer_cb;
	rllr->timer.data = rllr;

	bsc_schedule_timer(&rllr->timer, 10, 0);

	/* send the RSL RLL ESTablish REQuest */
	return rsl_establish_request(rllr->lchan, rllr->link_id);
}

/* Called from RSL code in case we have received an indication regarding
 * any RLL link */
void rll_indication(struct gsm_lchan *lchan, u_int8_t link_id, u_int8_t type)
{
	struct bsc_rll_req *rllr, *rllr2;

	llist_for_each_entry_safe(rllr, rllr2, &bsc_rll_reqs, list) {
		if (rllr->lchan == lchan &&
		    (rllr->link_id & LINKID_MASK) == (link_id & LINKID_MASK)) {
			bsc_del_timer(&rllr->timer);
			complete_rllr(rllr, type);
			return;
		}
	}
}
