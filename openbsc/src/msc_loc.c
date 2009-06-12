/* handler location updating request in the msc */
/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/msc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/db.h>
#include <openbsc/msgb.h>
#include <openbsc/signal.h>
#include <openbsc/talloc.h>
#include <openbsc/chan_alloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int msc_loc_upd_acc(struct gsm_lchan *lchan, u_int32_t tmsi);
static int msc_loc_upd_rej(struct gsm_lchan *lchan, u_int8_t cause);
static void schedule_reject(struct gsm_lchan *lchan);

static void *tall_locop_ctx;
static int authorize_everonye = 0;
static int reject_cause = 0;

void msc_loc_allow_everyone(int everyone)
{
	printf("Allowing everyone?\n");
	authorize_everonye = everyone;
}

void msc_loc_set_reject_cause(int cause)
{
	reject_cause = cause;
}

static const char *lupd_name(u_int8_t type)
{
	switch (type) {
	case GSM48_LUPD_NORMAL:
		return "NORMAL";
	case GSM48_LUPD_PERIODIC:
		return "PEROIDOC";
	case GSM48_LUPD_IMSI_ATT:
		return "IMSI ATTACH";
	default:
		return "UNKNOWN";
	}
}

static int authorize_subscriber(struct gsm_loc_updating_operation *loc,
				struct gsm_subscriber *subscriber)
{
	if (!subscriber)
		return 0;

	/*
	 * Do not send accept yet as more information should arrive. Some
	 * phones will not send us the information and we will have to check
	 * what we want to do with that.
	 */
	if (loc && (loc->waiting_for_imsi || loc->waiting_for_imei))
		return 0;

	if (authorize_everonye)
		return 1;

	return subscriber->authorized;
}

static void release_loc_updating_req(struct gsm_lchan *lchan)
{
	if (!lchan->loc_operation)
		return;

	bsc_del_timer(&lchan->loc_operation->updating_timer);
	talloc_free(lchan->loc_operation);
	lchan->loc_operation = 0;
	put_lchan(lchan);
}

static void allocate_loc_updating_req(struct gsm_lchan *lchan)
{
	use_lchan(lchan);
	release_loc_updating_req(lchan);

	if (!tall_locop_ctx)
		tall_locop_ctx = talloc_named_const(tall_bsc_ctx, 1,
						    "loc_updating_oper");
	lchan->loc_operation = talloc_zero(tall_locop_ctx,
					   struct gsm_loc_updating_operation);
}

static void loc_upd_rej_cb(void *data)
{
	struct gsm_lchan *lchan = data;

	release_loc_updating_req(lchan);
	msc_loc_upd_rej(lchan, reject_cause);
	lchan_auto_release(lchan);
}

static void schedule_reject(struct gsm_lchan *lchan)
{
	lchan->loc_operation->updating_timer.cb = loc_upd_rej_cb;
	lchan->loc_operation->updating_timer.data = lchan;
	bsc_schedule_timer(&lchan->loc_operation->updating_timer, 5, 0);
}

static int msc_authorize_subscr(struct gsm_lchan *lchan, struct msgb *msg)
{
	u_int32_t tmsi;

	if (authorize_subscriber(lchan->loc_operation, lchan->subscr)) {
		db_subscriber_alloc_tmsi(lchan->subscr);
		subscr_update(lchan->subscr, msg->trx->bts, GSM_SUBSCRIBER_UPDATE_ATTACHED);
		tmsi = strtoul(lchan->subscr->tmsi, NULL, 10);
		release_loc_updating_req(lchan);
		return msc_loc_upd_acc(msg->lchan, tmsi);
	}

	return 0;
}

static int msc_handle_lchan_signal(unsigned int subsys, unsigned int signal,
				   void *handler_data, void *signal_data)
{
	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	/*
	 * Cancel any outstanding location updating request
	 * operation taking place on the lchan.
	 */
	struct gsm_lchan *lchan = (struct gsm_lchan *)signal_data;
	if (!lchan)
		return 0;

	release_loc_updating_req(lchan);

	return 0;
}

/*
 * This will be ran by the linker when loading the DSO. We use it to
 * do system initialization, e.g. registration of signal handlers.
 */
static __attribute__((constructor)) void on_dso_load_msc_loc(void)
{
	register_signal_handler(SS_LCHAN, msc_handle_lchan_signal, NULL);
}

/* GSM 04.08 protocol implementation below */
/* Chapter 9.2.14 : Send LOCATION UPDATING REJECT */
int msc_loc_upd_rej(struct gsm_lchan *lchan, u_int8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;

	DEBUGP(DMM, "-> LOCATION UPDATING REJECT on channel: %d\n", lchan->nr);

	return gsm48_sendmsg(msg);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
int msc_loc_upd_acc(struct gsm_lchan *lchan, u_int32_t tmsi)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	u_int8_t *mid;
	int ret;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm0408_generate_lai(lai, bts->network->country_code,
		     bts->network->network_code, bts->location_area_code);

	mid = msgb_put(msg, GSM_MID_TMSI_LEN);
	generate_mid_from_tmsi(mid, tmsi);

	DEBUGP(DMM, "-> LOCATION UPDATE ACCEPT\n");

	ret = gsm48_sendmsg(msg);

	ret = gsm48_tx_mm_info(lchan);

	return ret;
}

/* Transmit Chapter 9.2.10 Identity Request */
static int mm_tx_identity_req(struct gsm_lchan *lchan, u_int8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_ID_REQ;
	gh->data[0] = id_type;

	return gsm48_sendmsg(msg);
}


/* Parse Chapter 9.2.11 Identity Response */
int msc_mm_rx_id_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM_MI_SIZE];

	gsm_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "IDENTITY RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (!lchan->subscr)
			lchan->subscr = db_create_subscriber(mi_string);
		if (lchan->loc_operation)
			lchan->loc_operation->waiting_for_imsi = 0;
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* update subscribe <-> IMEI mapping */
		if (lchan->subscr)
			db_subscriber_assoc_imei(lchan->subscr, mi_string);
		if (lchan->loc_operation)
			lchan->loc_operation->waiting_for_imei = 0;
		break;
	}

	/* Check if we can let the mobile station enter */
	return msc_authorize_subscr(lchan, msg);
}


/* Chapter 9.2.15: Receive Location Updating Request */
int msc_mm_rx_loc_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_loc_upd_req *lu;
	struct gsm_subscriber *subscr = NULL;
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t mi_type;
	char mi_string[GSM_MI_SIZE];
	int rc;

	lu = (struct gsm48_loc_upd_req *) gh->data;

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	gsm_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);

	DEBUGPC(DMM, "mi_type=0x%02x MI(%s) type=%s ", mi_type, mi_string,
		lupd_name(lu->type));

	/*
	 * Pseudo Spoof detection: Just drop a second/concurrent
	 * location updating request.
	 */
	if (lchan->loc_operation) {
		DEBUGPC(DMM, "ignoring request due an existing one: %p.\n",
			lchan->loc_operation);
		msc_loc_upd_rej(lchan, GSM48_REJECT_PROTOCOL_ERROR);
		return 0;
	}

	allocate_loc_updating_req(lchan);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		DEBUGPC(DMM, "\n");
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEI);
		lchan->loc_operation->waiting_for_imei = 1;

		/* look up subscriber based on IMSI */
		subscr = db_create_subscriber(mi_string);
		break;
	case GSM_MI_TYPE_TMSI:
		DEBUGPC(DMM, "\n");
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEI);
		lchan->loc_operation->waiting_for_imei = 1;

		/* look up the subscriber based on TMSI, request IMSI if it fails */
		subscr = subscr_get_by_tmsi(mi_string);
		if (!subscr) {
			/* send IDENTITY REQUEST message to get IMSI */
			rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMSI);
			lchan->loc_operation->waiting_for_imsi = 1;
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		DEBUGPC(DMM, "unimplemented mobile identity type\n");
		break;
	default:
		DEBUGPC(DMM, "unknown mobile identity type\n");
		break;
	}

	/* schedule the reject timer */
	schedule_reject(lchan);

	if (!subscr) {
		DEBUGPC(DRR, "<- Can't find any subscriber for this ID\n");
		/* FIXME: request id? close channel? */
		return -EINVAL;
	}

	lchan->subscr = subscr;

	/* check if we can let the subscriber into our network immediately
	 * or if we need to wait for identity responses. */
	return msc_authorize_subscr(lchan, msg);
}

int msc_mm_rx_imsi_detach_ind(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_imsi_detach_ind *idi =
				(struct gsm48_imsi_detach_ind *) gh->data;
	u_int8_t mi_type = idi->mi[0] & GSM_MI_TYPE_MASK;
	char mi_string[GSM_MI_SIZE];
	struct gsm_subscriber *subscr = NULL;

	gsm_mi_to_string(mi_string, sizeof(mi_string), idi->mi, idi->mi_len);
	DEBUGP(DMM, "IMSI DETACH INDICATION: mi_type=0x%02x MI(%s): ",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_get_by_tmsi(mi_string);
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_get_by_imsi(mi_string);
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		DEBUGPC(DMM, "unimplemented mobile identity type\n");
		break;
	default:
		DEBUGPC(DMM, "unknown mobile identity type\n");
		break;
	}

	if (subscr) {
		subscr_update(subscr, msg->trx->bts,
				GSM_SUBSCRIBER_UPDATE_DETACHED);
		DEBUGP(DMM, "Subscriber: %s\n",
		       subscr->name ? subscr->name : subscr->imsi);
		subscr_put(subscr);
	} else
		DEBUGP(DMM, "Unknown Subscriber ?!?\n");

	return 0;
}

