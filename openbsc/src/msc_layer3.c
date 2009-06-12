/* Layer3 handling of our built-in MSC */
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
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>

#include <string.h>


static int msc_rr_rx_pag_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t *classmark2_lv = gh->data + 1;
	u_int8_t *mi_lv = gh->data + 2 + *classmark2_lv;
	u_int8_t mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM_MI_SIZE];
	struct gsm_subscriber *subscr;
	struct paging_signal_data sig_data;

	gsm_mi_to_string(mi_string, sizeof(mi_string), mi_lv+1, *mi_lv);
	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_get_by_tmsi(mi_string);
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_get_by_imsi(mi_string);
		break;
	}

	if (!subscr) {
		DEBUGP(DRR, "<- Can't find any subscriber for this ID\n");
		/* FIXME: request id? close channel? */
		return -EINVAL;
	}

	subscr->equipment.classmark2_len = *classmark2_lv;
	memcpy(subscr->equipment.classmark2, classmark2_lv+1, *classmark2_lv);
	db_sync_equipment(&subscr->equipment);

	sig_data.subscr = subscr;
	sig_data.bts	= msg->lchan->ts->trx->bts;
	sig_data.lchan	= msg->lchan;

	dispatch_signal(SS_PAGING, S_PAGING_COMPLETED, &sig_data);
	return 0;
}

static int msc_rcv_rr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_CLSM_CHG:
		break;
	case GSM48_MT_RR_GPRS_SUSP_REQ:
		break;
	case GSM48_MT_RR_PAG_RESP:
		rc = msc_rr_rx_pag_resp(msg);
		break;
	case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
		break;
	case GSM48_MT_RR_STATUS:
		break;
	case GSM48_MT_RR_MEAS_REP:
		break;
	}

	return rc;
}

/*
 * GSM04.08 layer3 dispatch
 */
int msc_layer3(struct msgb *msg, void *data)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int rc = 0;

	switch (pdisc) {
	case GSM48_PDISC_RR:
		rc = msc_rcv_rr(msg);
		break;
	case GSM48_PDISC_CC:
		break;
	case GSM48_PDISC_MM:
		break;
	case GSM48_PDISC_SMS:
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		break;
	}

	return rc;
}
