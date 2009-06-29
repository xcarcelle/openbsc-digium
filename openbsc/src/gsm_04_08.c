/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface 
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/talloc.h>

#define GSM48_ALLOC_SIZE	1024
#define GSM48_ALLOC_HEADROOM	128

#define GSM_MAX_FACILITY       128
#define GSM_MAX_SSVERSION      128
#define GSM_MAX_USERUSER       128


static const char *rr_cause_names[] = {
	[GSM48_RR_CAUSE_NORMAL]			= "Normal event",
	[GSM48_RR_CAUSE_ABNORMAL_UNSPEC]	= "Abnormal release, unspecified",
	[GSM48_RR_CAUSE_ABNORMAL_UNACCT]	= "Abnormal release, channel unacceptable",
	[GSM48_RR_CAUSE_ABNORMAL_TIMER]		= "Abnormal release, timer expired",
	[GSM48_RR_CAUSE_ABNORMAL_NOACT]		= "Abnormal release, no activity on radio path",
	[GSM48_RR_CAUSE_PREMPTIVE_REL]		= "Preemptive release",
	[GSM48_RR_CAUSE_HNDOVER_IMP]		= "Handover impossible, timing advance out of range",
	[GSM48_RR_CAUSE_CHAN_MODE_UNACCT]	= "Channel mode unacceptable",
	[GSM48_RR_CAUSE_FREQ_NOT_IMPL]		= "Frequency not implemented",
	[GSM48_RR_CAUSE_CALL_CLEARED]		= "Call already cleared",
	[GSM48_RR_CAUSE_SEMANT_INCORR]		= "Semantically incorrect message",
	[GSM48_RR_CAUSE_INVALID_MAND_INF]	= "Invalid mandatory information",
	[GSM48_RR_CAUSE_MSG_TYPE_N]		= "Message type non-existant or not implemented",
	[GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT]	= "Message type not compatible with protocol state",
	[GSM48_RR_CAUSE_COND_IE_ERROR]		= "Conditional IE error",
	[GSM48_RR_CAUSE_NO_CELL_ALLOC_A]	= "No cell allocation available",
	[GSM48_RR_CAUSE_PROT_ERROR_UNSPC]	= "Protocol error unspecified",
};

static const char *cc_msg_names[] = {
	"unknown 0x00",
	"ALERTING",
	"CALL_PROC",
	"PROGRESS",
	"ESTAB",
	"SETUP",
	"ESTAB_CONF",
	"CONNECT",
	"CALL_CONF",
	"START_CC",
	"unknown 0x0a",
	"RECALL",
	"unknown 0x0c",
	"unknown 0x0d",
	"EMERG_SETUP",
	"CONNECT_ACK",
	"USER_INFO",
	"unknown 0x11",
	"unknown 0x12",
	"MODIFY_REJECT",
	"unknown 0x14",
	"unknown 0x15",
	"unknown 0x16",
	"MODIFY",
	"HOLD",
	"HOLD_ACK",
	"HOLD_REJ",
	"unknown 0x1b",
	"RETR",
	"RETR_ACK",
	"RETR_REJ",
	"MODIFY_COMPL",
	"unknown 0x20",
	"unknown 0x21",
	"unknown 0x22",
	"unknown 0x23",
	"unknown 0x24",
	"DISCONNECT",
	"unknown 0x26",
	"unknown 0x27",
	"unknown 0x28",
	"unknown 0x29",
	"RELEASE_COMPL",
	"unknown 0x2b",
	"unknown 0x2c",
	"RELEASE",
	"unknown 0x2e",
	"unknown 0x2f",
	"unknown 0x30",
	"STOP_DTMF",
	"STOP_DTMF_ACK",
	"unknown 0x33",
	"STATUS_ENQ",
	"START_DTMF",
	"START_DTMF_ACK",
	"START_DTMF_REJ",
	"unknown 0x38",
	"CONG_CTRL",
	"FACILITY",
	"unknown 0x3b",
	"STATUS",
	"unknown 0x3c",
	"NOTIFY",
	"unknown 0x3f",
};

static char strbuf[64];

static const char *rr_cause_name(u_int8_t cause)
{
	if (cause < ARRAY_SIZE(rr_cause_names) &&
	    rr_cause_names[cause])
		return rr_cause_names[cause];

	snprintf(strbuf, sizeof(strbuf), "0x%02x", cause);
	return strbuf;
}

const char *gsm48_cc_msg_name(u_int8_t cause)
{
	return cc_msg_names[cause];
}

static void parse_meas_rep(struct gsm_meas_rep *rep, const u_int8_t *data,
			   int len)
{
	memset(rep, 0, sizeof(*rep));

	if (data[0] & 0x80)
		rep->flags |= MEAS_REP_F_BA1;
	if (data[0] & 0x40)
		rep->flags |= MEAS_REP_F_DTX;
	if (data[1] & 0x40)
		rep->flags |= MEAS_REP_F_VALID;

	rep->rxlev_full = data[0] & 0x3f;
	rep->rxlev_sub = data[1] & 0x3f;
	rep->rxqual_full = (data[3] >> 4) & 0x7;
	rep->rxqual_sub = (data[3] >> 1) & 0x7;
	rep->num_cell = data[4] >> 6 | ((data[3] & 0x01) << 2);
	if (rep->num_cell < 1)
		return;

	/* an encoding nightmare in perfection */

	rep->cell[0].rxlev = data[4] & 0x3f;
	rep->cell[0].bcch_freq = data[5] >> 2;
	rep->cell[0].bsic = ((data[5] & 0x03) << 3) | (data[6] >> 5);
	if (rep->num_cell < 2)
		return;

	rep->cell[1].rxlev = ((data[6] & 0x1f) << 1) | (data[7] >> 7);
	rep->cell[1].bcch_freq = (data[7] >> 2) & 0x1f;
	rep->cell[1].bsic = ((data[7] & 0x03) << 4) | (data[8] >> 4);
	if (rep->num_cell < 3)
		return;

	rep->cell[2].rxlev = ((data[8] & 0x0f) << 2) | (data[9] >> 6);
	rep->cell[2].bcch_freq = (data[9] >> 1) & 0x1f;
	rep->cell[2].bsic = ((data[9] & 0x01) << 6) | (data[10] >> 3);
	if (rep->num_cell < 4)
		return;

	rep->cell[3].rxlev = ((data[10] & 0x07) << 3) | (data[11] >> 5);
	rep->cell[3].bcch_freq = data[11] & 0x1f;
	rep->cell[3].bsic = data[12] >> 2;
	if (rep->num_cell < 5)
		return;

	rep->cell[4].rxlev = ((data[12] & 0x03) << 4) | (data[13] >> 4);
	rep->cell[4].bcch_freq = ((data[13] & 0xf) << 1) | (data[14] >> 7);
	rep->cell[4].bsic = (data[14] >> 1) & 0x3f;
	if (rep->num_cell < 6)
		return;

	rep->cell[5].rxlev = ((data[14] & 0x01) << 5) | (data[15] >> 3);
	rep->cell[5].bcch_freq = ((data[15] & 0x07) << 2) | (data[16] >> 6);
	rep->cell[5].bsic = data[16] & 0x3f;
}

struct gsm_lai {
	u_int16_t mcc;
	u_int16_t mnc;
	u_int16_t lac;
};

static void to_bcd(u_int8_t *bcd, u_int16_t val)
{
	bcd[2] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[0] = val % 10;
	val = val / 10;
}

void gsm0408_generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc, 
			 u_int16_t mnc, u_int16_t lac)
{
	u_int8_t bcd[3];

	to_bcd(bcd, mcc);
	lai48->digits[0] = bcd[0] | (bcd[1] << 4);
	lai48->digits[1] = bcd[2];

	to_bcd(bcd, mnc);
	/* FIXME: do we need three-digit MNC? See Table 10.5.3 */
#if 0
	lai48->digits[1] |= bcd[2] << 4;
	lai48->digits[2] = bcd[0] | (bcd[1] << 4);
#else
	lai48->digits[1] |= 0xf << 4;
	lai48->digits[2] = bcd[1] | (bcd[2] << 4);
#endif
	
	lai48->lac = htons(lac);
}

int generate_mid_from_tmsi(u_int8_t *buf, u_int32_t tmsi)
{
	u_int32_t *tptr = (u_int32_t *) &buf[3];

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[1] = GSM_TMSI_LEN;
	buf[2] = 0xf0 | GSM_MI_TYPE_TMSI;
	*tptr = htonl(tmsi);

	return 7;
}

static const char bcd_num_digits[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', 
	'8', '9', '*', '#', 'a', 'b', 'c', '\0'
};

/* decode a 'called/calling/connect party BCD number' as in 10.5.4.7 */
int decode_bcd_number(char *output, int output_len, const u_int8_t *bcd_lv,
		      int h_len)
{
	u_int8_t in_len = bcd_lv[0];
	int i;

	for (i = 1 + h_len; i <= in_len; i++) {
		/* lower nibble */
		output_len--;
		if (output_len <= 1)
			break;
		*output++ = bcd_num_digits[bcd_lv[i] & 0xf];

		/* higher nibble */
		output_len--;
		if (output_len <= 1)
			break;
		*output++ = bcd_num_digits[bcd_lv[i] >> 4];
	}
	if (output_len >= 1)
		*output++ = '\0';

	return 0;
}

/* convert a single ASCII character to call-control BCD */
static int asc_to_bcd(const char asc)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bcd_num_digits); i++) {
		if (bcd_num_digits[i] == asc)
			return i;
	}
	return -EINVAL;
}

/* convert a ASCII phone number to 'called/calling/connect party BCD number' */
int encode_bcd_number(u_int8_t *bcd_lv, u_int8_t max_len,
		      int h_len, const char *input)
{
	int in_len = strlen(input);
	int i;
	u_int8_t *bcd_cur = bcd_lv + 1 + h_len;

	/* two digits per byte, plus type byte */
	bcd_lv[0] = in_len/2 + h_len;
	if (in_len % 2)
		bcd_lv[0]++;

	if (bcd_lv[0] > max_len)
		return -EIO;

	for (i = 0; i < in_len; i++) {
		int rc = asc_to_bcd(input[i]);
		if (rc < 0)
			return rc;
		if (i % 2 == 0)
			*bcd_cur = rc;	
		else
			*bcd_cur++ |= (rc << 4);
	}
	/* append padding nibble in case of odd length */
	if (i % 2)
		*bcd_cur++ |= 0xf0;

	/* return how many bytes we used */
	return (bcd_cur - bcd_lv);
}

struct msgb *gsm48_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM,
				   "GSM 04.08");
}

int gsm48_sendmsg(struct msgb *msg)
{
	if (msg->lchan) {
		struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->data;
		msg->trx = msg->lchan->ts->trx;

		if ((gh->proto_discr & GSM48_PDISC_MASK) == GSM48_PDISC_CC)
			DEBUGP(DCC, "(bts %d trx %d ts %d ti %02x) "
				"Sending '%s' to MS.\n", msg->trx->bts->nr,
				msg->trx->nr, msg->lchan->ts->nr,
				gh->proto_discr & 0xf0,
				cc_msg_names[gh->msg_type & 0x3f]);
		else
			DEBUGP(DCC, "(bts %d trx %d ts %d pd %02x) "
				"Sending 0x%02x to MS.\n", msg->trx->bts->nr,
				msg->trx->nr, msg->lchan->ts->nr,
				gh->proto_discr, gh->msg_type);
	}

	msg->l3h = msg->data;

	return rsl_data_request(msg, 0);
}

/* 9.1.5 Channel mode modify */
int gsm48_tx_chan_mode_modify(struct gsm_lchan *lchan, u_int8_t mode)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_chan_mode_modify *cmm =
		(struct gsm48_chan_mode_modify *) msgb_put(msg, sizeof(*cmm));
	u_int16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;

	DEBUGP(DRR, "-> CHANNEL MODE MODIFY mode=0x%02x\n", mode);

	lchan->tch_mode = mode;
	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_MODE_MODIF;

	/* fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd() */
	cmm->chan_desc.chan_nr = lchan2chan_nr(lchan);
	cmm->chan_desc.h0.tsc = lchan->ts->trx->bts->tsc;
	cmm->chan_desc.h0.h = 0;
	cmm->chan_desc.h0.arfcn_high = arfcn >> 8;
	cmm->chan_desc.h0.arfcn_low = arfcn & 0xff;
	cmm->mode = mode;

	return gsm48_sendmsg(msg);
}

#if 0
static u_int8_t to_bcd8(u_int8_t val)
{
       return ((val / 10) << 4) | (val % 10);
}
#endif

/* Section 9.2.15a */
int gsm48_tx_mm_info(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_network *net = lchan->ts->trx->bts->network;
	u_int8_t *ptr8;
	u_int16_t *ptr16;
	int name_len;
	int i;
#if 0
	time_t cur_t;
	struct tm* cur_time;
	int tz15min;
#endif

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_INFO;

	if (net->name_long) {
		name_len = strlen(net->name_long);
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len*2 +1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (u_int16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_long[i]);

		/* FIXME: Use Cell Broadcast, not UCS-2, since
		 * UCS-2 is only supported by later revisions of the spec */
	}

	if (net->name_short) {
		name_len = strlen(net->name_short);
		/* 10.5.3.5a */
		ptr8 = (u_int8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len*2 + 1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (u_int16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_short[i]);
	}

#if 0
	/* Section 10.5.3.9 */
	cur_t = time(NULL);
	cur_time = gmtime(&cur_t);
	ptr8 = msgb_put(msg, 8);
	ptr8[0] = GSM48_IE_NET_TIME_TZ;
	ptr8[1] = to_bcd8(cur_time->tm_year % 100);
	ptr8[2] = to_bcd8(cur_time->tm_mon);
	ptr8[3] = to_bcd8(cur_time->tm_mday);
	ptr8[4] = to_bcd8(cur_time->tm_hour);
	ptr8[5] = to_bcd8(cur_time->tm_min);
	ptr8[6] = to_bcd8(cur_time->tm_sec);
	/* 02.42: coded as BCD encoded signed value in units of 15 minutes */
	tz15min = (cur_time->tm_gmtoff)/(60*15);
	ptr8[7] = to_bcd8(tz15min);
	if (tz15min < 0)
		ptr8[7] |= 0x80;
#endif

	return gsm48_sendmsg(msg);
}

static int gsm48_tx_mm_serv_ack(struct gsm_lchan *lchan)
{
	DEBUGP(DMM, "-> CM SERVICE ACK\n");
	return gsm48_tx_simple(lchan, GSM48_PDISC_MM, GSM48_MT_MM_CM_SERV_ACC);
}

/* 9.2.6 CM service reject */
static int gsm48_tx_mm_serv_rej(struct gsm_lchan *lchan,
				enum gsm48_reject_value value)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);

	msg->lchan = lchan;
	use_lchan(lchan);

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;
	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return gsm48_sendmsg(msg);
}


/*
 * Handle CM Service Requests
 * a) Verify that the packet is long enough to contain the information
 *    we require otherwsie reject with INCORRECT_MESSAGE
 * b) Try to parse the TMSI. If we do not have one reject
 * c) Check that we know the subscriber with the TMSI otherwise reject
 *    with a HLR cause
 * d) Set the subscriber on the gsm_lchan and accept
 */
static int gsm48_rx_mm_serv_req(struct msgb *msg)
{
	u_int8_t mi_type;
	char mi_string[GSM_MI_SIZE];

	struct gsm_subscriber *subscr;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_service_request *req =
			(struct gsm48_service_request *)gh->data;
	/* unfortunately in Phase1 the classmar2 length is variable */
	u_int8_t classmark2_len = gh->data[1];
	u_int8_t *classmark2 = gh->data+2;
	u_int8_t mi_len = *(classmark2 + classmark2_len);
	u_int8_t *mi = (classmark2 + classmark2_len + 1);

	DEBUGP(DMM, "<- CM SERVICE REQUEST ");
	if (msg->data_len < sizeof(struct gsm48_service_request*)) {
		DEBUGPC(DMM, "wrong sized message\n");
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (msg->data_len < req->mi_len + 6) {
		DEBUGPC(DMM, "does not fit in packet\n");
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_INCORRECT_MESSAGE);
	}

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	if (mi_type != GSM_MI_TYPE_TMSI) {
		DEBUGPC(DMM, "mi_type is not TMSI: %d\n", mi_type);
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_INCORRECT_MESSAGE);
	}

	gsm_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
	DEBUGPC(DMM, "serv_type=0x%02x mi_type=0x%02x M(%s)\n",
		req->cm_service_type, mi_type, mi_string);

	subscr = subscr_get_by_tmsi(mi_string);

	/* FIXME: if we don't know the TMSI, inquire abit IMSI and allocate new TMSI */
	if (!subscr)
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_IMSI_UNKNOWN_IN_HLR);

	if (!msg->lchan->subscr)
		msg->lchan->subscr = subscr;
	else if (msg->lchan->subscr != subscr) {
		DEBUGP(DMM, "<- CM Channel already owned by someone else?\n");
		subscr_put(subscr);
	}

	subscr->equipment.classmark2_len = classmark2_len;
	memcpy(subscr->equipment.classmark2, classmark2, classmark2_len);
	db_sync_equipment(&subscr->equipment);

	return gsm48_tx_mm_serv_ack(msg->lchan);
}

static int gsm48_rx_mm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "MM STATUS (reject cause 0x%02x)\n", gh->data[0]);

	return 0;
}

/* Receive a GSM 04.08 Mobility Management (MM) message */
static int gsm0408_rcv_mm(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		break;
	case GSM48_MT_MM_ID_RESP:
		break;
	case GSM48_MT_MM_CM_SERV_REQ:
		rc = gsm48_rx_mm_serv_req(msg);
		break;
	case GSM48_MT_MM_STATUS:
		rc = gsm48_rx_mm_status(msg);
		break;
	case GSM48_MT_MM_TMSI_REALL_COMPL:
		DEBUGP(DMM, "TMSI Reallocation Completed. Subscriber: %s\n",
		       msg->lchan->subscr ?
				msg->lchan->subscr->imsi :
				"unknown subscriber");
		break;
	case GSM48_MT_MM_IMSI_DETACH_IND:
		break;
	case GSM48_MT_MM_CM_REEST_REQ:
		DEBUGP(DMM, "CM REESTABLISH REQUEST: Not implemented\n");
		break;
	case GSM48_MT_MM_AUTH_RESP:
		DEBUGP(DMM, "AUTHENTICATION RESPONSE: Not implemented\n");
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/*
 * Receive a PAGING RESPONSE message from the MS. Inside the BSC
 * we will only have to stop the paging as it was successful and
 * event this is against the spec... see GSM 08.08 3.1.16.
 */
static int gsm48_rr_rx_pag_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t *classmark2_lv = gh->data + 1;
	u_int8_t *mi_lv = gh->data + 2 + *classmark2_lv;
	u_int8_t mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM_MI_SIZE];
	struct gsm_subscriber *subscr = NULL;

	gsm_mi_to_string(mi_string, sizeof(mi_string), mi_lv+1, *mi_lv);
	DEBUGP(DRR, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);
	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_find_by_tmsi(mi_string);
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_find_by_imsi(mi_string);
		break;
	}

	if (!subscr) {
		DEBUGP(DRR, "<- Can't find any subscriber for this ID\n");
		/* FIXME: request id? close channel? */
		return -EINVAL;
	}

	DEBUGP(DRR, "<- Channel was requested by %s\n",
		subscr->name ? subscr->name : subscr->imsi);

	if (!msg->lchan->subscr) {
		msg->lchan->subscr = subscr;
	} else if (msg->lchan->subscr != subscr) {
		DEBUGP(DRR, "<- Channel already owned by someone else?\n");
		subscr_put(subscr);
		return -EINVAL;
	} else {
		DEBUGP(DRR, "<- Channel already owned by us\n");
		subscr_put(subscr);
		subscr = msg->lchan->subscr;
	}

	/* Stop paging on the bts we received the paging response */
	paging_request_stop(msg->trx->bts, subscr, msg->lchan);
	return 0;
}

static int gsm48_rx_rr_classmark(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_subscriber *subscr = msg->lchan->subscr;
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	u_int8_t cm2_len, cm3_len = 0;
	u_int8_t *cm2, *cm3 = NULL;

	DEBUGP(DRR, "CLASSMARK CHANGE ");

	/* classmark 2 */
	cm2_len = gh->data[0];
	cm2 = &gh->data[1];
	DEBUGPC(DRR, "CM2(len=%u) ", cm2_len);

	if (payload_len > cm2_len + 1) {
		/* we must have a classmark3 */
		if (gh->data[cm2_len+1] != 0x20) {
			DEBUGPC(DRR, "ERR CM3 TAG\n");
			return -EINVAL;
		}
		if (cm2_len > 3) {
			DEBUGPC(DRR, "CM2 too long!\n");
			return -EINVAL;
		}
		
		cm3_len = gh->data[cm2_len+2];
		cm3 = &gh->data[cm2_len+3];
		if (cm3_len > 14) {
			DEBUGPC(DRR, "CM3 len %u too long!\n", cm3_len);
			return -EINVAL;
		}
		DEBUGPC(DRR, "CM3(len=%u)\n", cm3_len);
	}
	if (subscr) {
		subscr->equipment.classmark2_len = cm2_len;
		memcpy(subscr->equipment.classmark2, cm2, cm2_len);
		if (cm3) {
			subscr->equipment.classmark3_len = cm3_len;
			memcpy(subscr->equipment.classmark3, cm3, cm3_len);
		}
		db_sync_equipment(&subscr->equipment);
	}

	return 0;
}

static int gsm48_rx_rr_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DRR, "STATUS rr_cause = %s\n", 
		rr_cause_name(gh->data[0]));

	return 0;
}

static int gsm48_rx_rr_meas_rep(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	static struct gsm_meas_rep meas_rep;

	DEBUGP(DMEAS, "MEASUREMENT REPORT ");
	parse_meas_rep(&meas_rep, gh->data, payload_len);
	if (meas_rep.flags & MEAS_REP_F_DTX)
		DEBUGPC(DMEAS, "DTX ");
	if (meas_rep.flags & MEAS_REP_F_BA1)
		DEBUGPC(DMEAS, "BA1 ");
	if (!(meas_rep.flags & MEAS_REP_F_VALID))
		DEBUGPC(DMEAS, "NOT VALID ");
	else
		DEBUGPC(DMEAS, "FULL(lev=%u, qual=%u) SUB(lev=%u, qual=%u) ",
		meas_rep.rxlev_full, meas_rep.rxqual_full, meas_rep.rxlev_sub,
		meas_rep.rxqual_sub);

	DEBUGPC(DMEAS, "NUM_NEIGH=%u\n", meas_rep.num_cell);

	/* FIXME: put the results somwhere */

	return 0;
}

/* Receive a GSM 04.08 Radio Resource (RR) message */
static int gsm0408_rcv_rr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_CLSM_CHG:
		rc = gsm48_rx_rr_classmark(msg);
		break;
	case GSM48_MT_RR_GPRS_SUSP_REQ:
		DEBUGP(DRR, "GRPS SUSPEND REQUEST\n");
		break;
	case GSM48_MT_RR_PAG_RESP:
		rc = gsm48_rr_rx_pag_resp(msg);
		break;
	case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
		DEBUGP(DRR, "CHANNEL MODE MODIFY ACK\n");
		rc = rsl_chan_mode_modify_req(msg->lchan);
		break;
	case GSM48_MT_RR_STATUS:
		rc = gsm48_rx_rr_status(msg);
		break;
	case GSM48_MT_RR_MEAS_REP:
		rc = gsm48_rx_rr_meas_rep(msg);
		break;
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 RR msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* 7.1.7 and 9.1.7 Channel release*/
int gsm48_send_rr_release(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause;

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_REL;

	cause = msgb_put(msg, 1);
	cause[0] = GSM48_RR_CAUSE_NORMAL;

	DEBUGP(DRR, "Sending Channel Release: Chan: Number: %d Type: %d\n",
		lchan->nr, lchan->type);

	return gsm48_sendmsg(msg);
}

int gsm48_tx_simple(struct gsm_lchan *lchan,
		    u_int8_t pdisc, u_int8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = lchan;

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gsm48_sendmsg(msg);
}

/* here we pass in a msgb from the RSL->RLL.  We expect the l3 pointer to be set */
int gsm0408_rcvmsg(struct msgb *msg)
{
	struct gsm_network *network = msg->trx->bts->network;

	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int rc = 0;
	
	switch (pdisc) {
	case GSM48_PDISC_CC:
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(msg);
		break;
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(msg);
		break;
	case GSM48_PDISC_SMS:
		rc = gsm0411_rcv_sms(msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		fprintf(stderr, "Unimplemented GSM 04.08 discriminator 0x%02d\n",
			pdisc);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 discriminator 0x%02d\n",
			pdisc);
		break;
	}

	if (network->gsm_layer3)
		network->gsm_layer3(msg, network->gsm_layer3_data);

	return rc;
}

/* Section 9.1.8 / Table 9.9 */
struct chreq {
	u_int8_t val;
	u_int8_t mask;
	enum chreq_type type;
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 1 */
static const struct chreq chreq_type_neci1[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_F },
	{ 0x68, 0xfc, CHREQ_T_CALL_REEST_TCH_H },
	{ 0x6c, 0xfc, CHREQ_T_CALL_REEST_TCH_H_DBL },
	{ 0xe0, 0xe0, CHREQ_T_SDCCH },
	{ 0x40, 0xf0, CHREQ_T_VOICE_CALL_TCH_H },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xf0, CHREQ_T_LOCATION_UPD },
	{ 0x10, 0xf0, CHREQ_T_SDCCH },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 0 */
static const struct chreq chreq_type_neci0[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_H },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xe0, CHREQ_T_LOCATION_UPD },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
};

static const enum gsm_chan_t ctype_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_SDCCH]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_TCH_F]			= GSM_LCHAN_TCH_F,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_LOCATION_UPD]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_LCHAN_TCH_F,
};

static const enum gsm_chreq_reason_t reason_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_CHREQ_REASON_EMERG,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_SDCCH]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_TCH_F]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_LOCATION_UPD]		= GSM_CHREQ_REASON_LOCATION_UPD,
	[CHREQ_T_PAG_R_ANY]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_CHREQ_REASON_PAG,
};

enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra)
{
	int i;
	/* FIXME: determine if we set NECI = 0 in the BTS SI4 */

	for (i = 0; i < ARRAY_SIZE(chreq_type_neci0); i++) {
		const struct chreq *chr = &chreq_type_neci0[i];
		if ((ra & chr->mask) == chr->val)
			return ctype_by_chreq[chr->type];
	}
	fprintf(stderr, "Unknown CHANNEL REQUEST RQD 0x%02x\n", ra);
	return GSM_LCHAN_SDCCH;
}

enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra)
{
	int i;
	/* FIXME: determine if we set NECI = 0 in the BTS SI4 */

	for (i = 0; i < ARRAY_SIZE(chreq_type_neci0); i++) {
		const struct chreq *chr = &chreq_type_neci0[i];
		if ((ra & chr->mask) == chr->val)
			return reason_by_chreq[chr->type];
	}
	fprintf(stderr, "Unknown CHANNEL REQUEST REASON 0x%02x\n", ra);
	return GSM_CHREQ_REASON_OTHER;
}

/* dequeue messages to layer 4 */
int bsc_upqueue(struct gsm_network *net)
{
	struct gsm_mncc *mncc;
	struct msgb *msg;
	int work = 0;

	if (net)
		while ((msg = msgb_dequeue(&net->upqueue))) {
			mncc = (struct gsm_mncc *)msg->data;
			if (net->mncc_recv)
				net->mncc_recv(net, mncc->msg_type, mncc);
			work = 1; /* work done */
			talloc_free(msg);
		}

	return work;
}
