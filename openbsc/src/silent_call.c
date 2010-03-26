/* GSM silent call feature */

/*
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <openbsc/msgb.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>

/* paging of the requested subscriber has completed */
static int paging_cb_silent(unsigned int hooknum, unsigned int event,
			    struct msgb *msg, void *_lchan, void *_data)
{
	struct gsm_lchan *lchan = _lchan;
	struct scall_signal_data sigdata;
	int rc;

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	DEBUGP(DSMS, "paging_cb_silent: ");

	sigdata.lchan = lchan;
	sigdata.data = _data;

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
		DEBUGPC(DSMS, "success, using Timeslot %u on ARFCN %u\n",
			lchan->ts->nr, lchan->ts->trx->arfcn);
		lchan->silent_call = 1;
		/* increment lchan reference count */
		dispatch_signal(SS_SCALL, S_SCALL_SUCCESS, &sigdata);
		use_lchan(lchan);
		break;
	case GSM_PAGING_EXPIRED:
		DEBUGP(DSMS, "expired\n");
		dispatch_signal(SS_SCALL, S_SCALL_EXPIRED, &sigdata);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* receive a layer 3 message from a silent call */
int silent_call_rx(struct msgb *msg)
{
	/* FIXME: do something like sending it through a UDP port */
	return 0;
}

struct msg_match {
	u_int8_t pdisc;
	u_int8_t msg_type;
};

/* list of messages that are handled inside OpenBSC, even in a silent call */
static const struct msg_match silent_call_accept[] = {
	{ GSM48_PDISC_MM, GSM48_MT_MM_LOC_UPD_REQUEST },
	{ GSM48_PDISC_MM, GSM48_MT_MM_CM_SERV_REQ },
};

/* decide if we need to reroute a message as part of a silent call */
int silent_call_reroute(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int i;

	/* if we're not part of a silent call, never reroute */
	if (!msg->lchan->silent_call)
		return 0;

	/* check if we are a special message that is handled in openbsc */
	for (i = 0; i < ARRAY_SIZE(silent_call_accept); i++) {
		if (silent_call_accept[i].pdisc == pdisc &&
		    silent_call_accept[i].msg_type == gh->msg_type)
			return 0;
	}

	/* otherwise, reroute */
	return 1;
}


/* initiate a silent call with a given subscriber */
int gsm_silent_call_start(struct gsm_subscriber *subscr, void *data, int type)
{
	int rc;

	rc = paging_request(subscr->net, subscr, type,
			    paging_cb_silent, data);
	return rc;
}

/* end a silent call with a given subscriber */
int gsm_silent_call_stop(struct gsm_subscriber *subscr)
{
	struct gsm_lchan *lchan;

	lchan = lchan_for_subscr(subscr);
	if (!lchan)
		return -EINVAL;

	/* did we actually establish a silent call for this guy? */
	if (!lchan->silent_call)
		return -EINVAL;

	put_lchan(lchan);

	return 0;
}
