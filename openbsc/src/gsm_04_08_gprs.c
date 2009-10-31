/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>

#include <openbsc/db.h>
#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/talloc.h>
#include <openbsc/transaction.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_sgsn.h>

static const char *att_name(u_int8_t type)
{
	switch (type) {
	case GPRS_ATT_T_ATTACH:
		return "GPRS attach";
	case GPRS_ATT_T_ATT_WHILE_IMSI:
		return "GPRS attach while IMSI attached";
	case GPRS_ATT_T_COMBINED:
		return "Combined GPRS/IMSI attach";
	default:
		return "unknown";
	}
}

static const char *upd_name(u_int8_t type)
{
	switch (type) {
	case GPRS_UPD_T_RA:
		return "RA updating";
	case GPRS_UPD_T_RA_LA:
		return "combined RA/LA updating";
	case GPRS_UPD_T_RA_LA_IMSI_ATT:
		return "combined RA/LA updating + IMSI attach";
	case GPRS_UPD_T_PERIODIC:
		return "periodic updating";
	}
}

void gsm48_parse_ra(struct gprs_ra_id *raid, u_int8_t *buf)
{
	raid->mcc = (buf[0] & 0xf) * 100;
	raid->mcc += (buf[0] >> 4) * 10;
	raid->mcc += (buf[1] & 0xf) * 1;

	/* I wonder who came up with the stupidity of encoding the MNC
	 * differently depending on how many digits its decimal number has! */
	if ((buf[1] >> 4) == 0xf) {
		raid->mnc = (buf[2] & 0xf) * 10;
		raid->mnc += (buf[2] >> 4) * 1;
	} else {
		raid->mnc = (buf[2] & 0xf) * 100;
		raid->mnc += (buf[2] >> 4) * 10;
		raid->mnc += (buf[1] >> 4) * 1;
	}

	raid->lac = ntohs(*(u_int16_t *)(buf + 3));
	raid->rac = buf[5];
}

static int gsm48_construct_ra(u_int8_t *buf, const struct gprs_ra_id *raid)
{
	u_int16_t mcc = raid->mcc;
	u_int16_t mnc = raid->mnc;

	buf[0] = ((mcc / 100) % 10) | (((mcc / 10) % 10) << 4);
	buf[1] = (mcc % 10);

	/* I wonder who came up with the stupidity of encoding the MNC
	 * differently depending on how many digits its decimal number has! */
	if (mnc < 100) {
		buf[1] |= 0xf0;
		buf[2] = ((mnc / 10) % 10) | ((mnc % 10) << 4);
	} else {
		buf[1] |= (mnc % 10) << 4;
		buf[2] = ((mnc / 100) % 10) | (((mcc / 10) % 10) << 4);
	}

	*(u_int16_t *)(buf+3) = htons(raid->lac);

	buf[5] = raid->rac;

	return 6;
}
/* Send a message through the underlying layer */
static int gsm48_gmm_sendmsg(struct msgb *msg, int command)
{
	return gprs_llc_tx_ui(msg, GPRS_SAPI_GMM, command);
}

/* TS 03.03 Chapter 2.6 */
int gprs_tlli_type(u_int32_t tlli)
{
	if ((tlli & 0xc0000000) == 0xc0000000)
		return TLLI_LOCAL;
	else if ((tlli & 0xc0000000) == 0x80000000)
		return TLLI_FOREIGN;
	else if ((tlli & 0xf8000000) == 0x78000000)
		return TLLI_RANDOM;
	else if ((tlli & 0xf8000000) == 0x70000000)
		return TLLI_AUXILIARY;

	return TLLI_RESERVED;
}

/* Chapter 9.4.2: Attach accept */
static int gsm48_tx_gmm_att_ack(struct msgb *old_msg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_attach_ack *aa;

	DEBUGP(DMM, "<- GPRS ATTACH ACCEPT\n");

	msg->tlli = old_msg->tlli;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_ACK;

	aa = (struct gsm48_att_ack *) msgb_put(msg, sizeof(*aa));
	aa->force_stby = 0;	/* not indicated */
	aa->att_result = 1;	/* GPRS only */
	aa->ra_upd_timer = GPRS_TMR_MINUTE | 10;
	aa->radio_prio = 4;	/* lowest */
	gsm48_ra_id_by_bts(&aa->ra_id, old_msg->trx->bts);

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0);
}

/* Chapter 9.4.5: Attach reject */
static int gsm48_tx_gmm_att_rej(struct msgb *old_msg, u_int8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "<- GPRS ATTACH REJECT\n");

	msg->tlli = old_msg->tlli;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0);
}

/* Transmit Chapter 9.4.12 Identity Request */
static int gsm48_tx_gmm_id_req(struct msgb *old_msg, u_int8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "-> GPRS IDENTITY REQUEST\n");

	msg->tlli = old_msg->tlli;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_REQ;
	/* 10.5.5.9 ID type 2 + identity type and 10.5.5.7 'force to standby' IE */
	gh->data[0] = id_type & 0xf;

	return gsm48_gmm_sendmsg(msg, 0);
}

/* Check if we can already authorize a subscriber */
static int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	if (strlen(ctx->imei) && strlen(ctx->imsi)) {
		ctx->mm_state = GMM_REGISTERED_NORMAL;
		return gsm48_tx_gmm_att_ack(msg);
	}

	return 0;
}

/* Parse Chapter 9.4.13 Identity Response */
static int gsm48_rx_gmm_id_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->gmmh;
	u_int8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];
	struct gprs_ra_id ra_id;
	struct sgsn_mm_ctx *ctx;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "GMM IDENTITY RESPONSE: mi_type=0x%02x MI(%s) ",
		mi_type, mi_string);

	gsm48_ra_id_by_bts(&ra_id, msg->trx->bts);
	ctx = sgsn_mm_ctx_by_tlli(msg->tlli, &ra_id);
	if (!ctx) {
		DEBUGP(DMM, "from unknown TLLI 0x%08x?!?\n", msg->tlli);
		return -EINVAL;
	}

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* we already have a mm context with current TLLI, but no
		 * P-TMSI / IMSI yet.  What we now need to do is to fill
		 * this initial context with data from the HLR */
		strncpy(ctx->imsi, mi_string, sizeof(ctx->imei));
		break;
	case GSM_MI_TYPE_IMEI:
		strncpy(ctx->imei, mi_string, sizeof(ctx->imei));
		break;
	case GSM_MI_TYPE_IMEISV:
		break;
	}

	DEBUGPC(DMM, "\n");
	/* Check if we can let the mobile station enter */
	return gsm48_gmm_authorize(ctx, msg);
}

static void attach_rej_cb(void *data)
{
	struct sgsn_mm_ctx *ctx = data;

	gsm48_tx_gmm_att_rej(ctx->tlli, GMM_CAUSE_MS_ID_NOT_DERIVED);
	ctx->mm_state = GMM_DEREGISTERED;
	/* FIXME: release the context */
}

static void schedule_reject(struct sgsn_mm_ctx *ctx)
{
	ctx->T = 3370;
	ctx->timer.cb = attach_rej_cb;
	ctx->timer.data = ctx;
	bsc_schedule_timer(&ctx->timer, 6, 0);
}

/* Section 9.4.1 Attach request */
static int gsm48_rx_gmm_att_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->gmmh;
	u_int8_t *cur = gh->data, *msnc, *mi, *old_ra_info;
	u_int8_t msnc_len, att_type, mi_len, mi_type;
	u_int16_t drx_par;
	u_int32_t tmsi;
	char mi_string[GSM48_MI_SIZE];
	struct gprs_ra_id ra_id;
	struct sgsn_mm_ctx *ctx;

	DEBUGP(DMM, "GMM ATTACH REQUEST ");

	/* As per TS 04.08 Chapter 4.7.1.4, the attach request arrives either
	 * with a foreign TLLI (P-TMSI that was allocated to the MS before),
	 * or with random TLLI. */

	gsm48_ra_id_by_bts(&ra_id, msg->trx->bts);

	/* MS network capability 10.5.5.12 */
	msnc_len = *cur++;
	msnc = cur;
	if (msnc_len > 2)
		goto err_inval;
	cur += msnc_len;

	/* aTTACH Type 10.5.5.2 */
	att_type = *cur++ & 0x0f;

	/* DRX parameter 10.5.5.6 */
	drx_par = *cur++;
	drx_par |= *cur++ << 8;

	/* Mobile Identity (P-TMSI or IMSI) 10.5.1.4 */
	mi_len = *cur++;
	mi = cur;
	if (mi_len > 8)
		goto err_inval;
	mi_type = *mi & GSM_MI_TYPE_MASK;
	cur += mi_len;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	DEBUGPC(DMM, "MI(%s) type=\"%s\" ", mi_string, att_name(att_type));

	/* Old routing area identification 10.5.5.15 */
	old_ra_info = cur;
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status */

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* Try to find MM context based on IMSI */
		ctx = sgsn_mm_ctx_by_imsi(mi_string);
		if (!ctx) {
#if 0
			return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_IMSI_UNKNOWN);
#else
			/* As a temorary hack, we simply assume that the IMSI exists */
			ctx = sgsn_mm_ctx_alloc(0, &ra_id);
			if (!ctx)
				return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_NET_FAIL);
			strncpy(ctx->imsi, mi_string, sizeof(ctx->imsi));
#endif
		}
		/* we always want the IMEI, too */
		gsm48_tx_gmm_id_req(msg, GSM_MI_TYPE_IMSI);
		/* FIXME: Start some timer */
		ctx->mm_state = GMM_COMMON_PROC_INIT;
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = strtoul(mi_string, NULL, 10);
		/* Try to find MM context based on P-TMSI */
		ctx = sgsn_mm_ctx_by_ptmsi(tmsi);
		if (!ctx) {
			ctx = sgsn_mm_ctx_alloc(msg->tlli, &ra_id);
			/* Send MM INFO request for IMSI */
			gsm48_tx_gmm_id_req(msg, GSM_MI_TYPE_IMSI);
			/* FIXME: Start some timer */
			ctx->mm_state = GMM_COMMON_PROC_INIT;
		}
		break;
	default:
		break;
	}

	/* FIXME: allocate a new P-TMSI (+ P-TMSI signature) */
	/* FIXME: update the TLLI with the new local TLLI based on the P-TMSI */

	//return gsm48_tx_gmm_att_ack(msg);
	return 0;

err_inval:
	DEBUGPC(DMM, "\n");
	return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_SEM_INCORR_MSG);
}

/* Chapter 9.4.15: Routing area update accept */
static int gsm48_tx_gmm_ra_upd_ack(struct msgb *old_msg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_ra_upd_ack *rua;

	DEBUGP(DMM, "<- ROUTING AREA UPDATE ACCEPT\n");

	msg->tlli = old_msg->tlli;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_ACK;

	rua = (struct gsm48_ra_upd_ack *) msgb_put(msg, sizeof(*rua));
	rua->force_stby = 0;	/* not indicated */
	rua->upd_result = 0;	/* RA updated */
	rua->ra_upd_timer = GPRS_TMR_MINUTE | 10;
	/* FIXME: use values from the BTS */
	rua->ra_id.digits[0] = 0x00;
	rua->ra_id.digits[1] = 0xf1;
	rua->ra_id.digits[2] = 0x10;
	rua->ra_id.lac = htons(1);
	rua->ra_id.rac = 1;

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0);
}

/* Chapter 9.4.17: Routing area update reject */
static int gsm48_tx_gmm_ra_upd_rej(struct msgb *old_msg, u_int8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "<- ROUTING AREA UPDATE REJECT\n");

	msg->tlli = old_msg->tlli;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_REJ;
	gh->data[0] = cause;
	gh->data[1] = 0; /* ? */

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0);
}

/* Chapter 9.4.14: Routing area update request */
static int gsm48_rx_gmm_ra_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->gmmh;
	struct sgsn_mm_ctx *mmctx;
	u_int8_t *cur = gh->data;
	struct gprs_ra_id old_ra_id;
	u_int8_t upd_type;

	/* Update Type 10.5.5.18 */
	upd_type = *cur++ & 0x0f;

	DEBUGP(DMM, "GMM RA UPDATE REQUEST type=\"%s\" ", upd_name(upd_type));

	/* Old routing area identification 10.5.5.15 */
	gsm48_parse_ra(&old_ra_id, cur);
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status,
	 * DRX parameter, MS network capability */

	switch (upd_type) {
	case GPRS_UPD_T_RA_LA:
	case GPRS_UPD_T_RA_LA_IMSI_ATT:
		DEBUGPC(DMM, " unsupported in Mode III, is your SI13 corrupt?\n");
		return gsm48_tx_gmm_ra_upd_rej(msg, GMM_CAUSE_PROTO_ERR_UNSPEC);
		break;
	case GPRS_UPD_T_RA:
	case GPRS_UPD_T_PERIODIC:
		break;
	}

	/* Look-up the MM context based on old RA-ID and TLLI */
	mmctx = sgsn_mm_ctx_by_tlli(msg->tlli, &old_ra_id);
	if (!mmctx || mmctx->mm_state == GMM_DEREGISTERED) {
		/* The MS has to perform GPRS attach */
		DEBUGPC(DMM, " REJECT\n");
		return gsm48_tx_gmm_ra_upd_rej(msg, GMM_CAUSE_IMPL_DETACHED);
	}

	/* FIXME: Update the MM context with the new RA-ID */
	/* FIXME: Update the MM context with the new TLLI */
	/* FIXME: Update the MM context with the MS radio acc capabilities */
	/* FIXME: Update the MM context with the MS network capabilities */

	DEBUGPC(DMM, " ACCEPT\n");
	return gsm48_tx_gmm_ra_upd_ack(msg);
}

/* GPRS Mobility Management */
static int gsm0408_rcv_gmm(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->gmmh;
	int rc;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_GMM_RA_UPD_REQ:
		rc = gsm48_rx_gmm_ra_upd_req(msg);
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		rc = gsm48_rx_gmm_att_req(msg);
		break;
	case GSM48_MT_GMM_ID_RESP:
		rc = gsm48_rx_gmm_id_resp(msg);
		break;
	case GSM48_MT_GMM_RA_UPD_COMPL:
		/* only in case SGSN offered new P-TMSI */
	case GSM48_MT_GMM_ATTACH_COMPL:
		/* only in case SGSN offered new P-TMSI */
	case GSM48_MT_GMM_DETACH_REQ:
	case GSM48_MT_GMM_PTMSI_REALL_COMPL:
	case GSM48_MT_GMM_AUTH_CIPH_RESP:
	case GSM48_MT_GMM_STATUS:
		fprintf(stderr, "Unimplemented GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* Main entry point for incoming 04.08 GPRS messages */
int gsm0408_gprs_rcvmsg(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->gmmh;
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int rc = -EINVAL;

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(msg);
		break;
	case GSM48_PDISC_SM_GPRS:
		fprintf(stderr, "Unimplemented GSM 04.08 discriminator 0x%02x\n",
			pdisc);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 discriminator 0x%02x\n",
			pdisc);
		break;
	}

	return rc;
}

/* Determine the 'struct gsm_bts' from a RA ID */
struct gsm_bts *gsm48_bts_by_ra_id(struct gsm_network *net,
				   u_int8_t *buf, unsigned int len)
{
	struct gprs_ra_id raid;
	struct gsm_bts *bts;

	if (len < 6)
		return NULL;

	gsm48_parse_ra(&raid, buf);

	if (net->country_code != raid.mcc ||
	    net->network_code != raid.mnc)
		return NULL;

	llist_for_each_entry(bts, &net->bts_list, list) {
		/* FIXME: we actually also need to check the
		 * routing area code! */
		if (bts->location_area_code == raid.lac)
			return bts;
	}

	return NULL;
}

int gsm48_ra_id_by_bts(u_int8_t *buf, struct gsm_bts *bts)
{
	struct gprs_ra_id raid;

	raid.mcc = bts->network->country_code;
	raid.mnc = bts->network->network_code;
	raid.lac = bts->location_area_code;
	raid.rac = 0;	/* FIXME */

	return gsm48_construct_ra(buf, &raid);
}