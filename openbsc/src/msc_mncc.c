/* Layer3 to Layer4 call handling */
/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/signal.h>
#include <openbsc/paging.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <openbsc/talloc.h>

static void free_trans(struct gsm_trans *trans);
int mncc_release_ind(struct gsm_network *net, struct gsm_trans *trans,
		     u_int32_t callref, int location, int value);
static int msc_cc_tx_setup(struct gsm_trans *trans, void *arg);

static u_int32_t new_callref = 0x80000001;
static void *tall_trans_ctx;
static const struct tlv_definition rsl_att_tlvdef = {
	.def = {
		[GSM48_IE_MOBILE_ID]	= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_LONG]	= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_SHORT]	= { TLV_TYPE_TLV },
		[GSM48_IE_UTC]		= { TLV_TYPE_TV },
		[GSM48_IE_NET_TIME_TZ]	= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_LSA_IDENT]	= { TLV_TYPE_TLV },

		[GSM48_IE_BEARER_CAP]	= { TLV_TYPE_TLV },
		[GSM48_IE_CAUSE]	= { TLV_TYPE_TLV },
		[GSM48_IE_CC_CAP]	= { TLV_TYPE_TLV },
		[GSM48_IE_ALERT]	= { TLV_TYPE_TLV },
		[GSM48_IE_FACILITY]	= { TLV_TYPE_TLV },
		[GSM48_IE_PROGR_IND]	= { TLV_TYPE_TLV },
		[GSM48_IE_AUX_STATUS]	= { TLV_TYPE_TLV },
		[GSM48_IE_NOTIFY]	= { TLV_TYPE_TV },
		[GSM48_IE_KPD_FACILITY]	= { TLV_TYPE_TV },
		[GSM48_IE_SIGNAL]	= { TLV_TYPE_TV },
		[GSM48_IE_CONN_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CONN_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLING_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLING_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLED_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLED_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_REDIR_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_REDIR_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_LOWL_COMPAT]	= { TLV_TYPE_TLV },
		[GSM48_IE_HIGHL_COMPAT]	= { TLV_TYPE_TLV },
		[GSM48_IE_USER_USER]	= { TLV_TYPE_TLV },
		[GSM48_IE_SS_VERS]	= { TLV_TYPE_TLV },
		[GSM48_IE_MORE_DATA]	= { TLV_TYPE_T },
		[GSM48_IE_CLIR_SUPP]	= { TLV_TYPE_T },
		[GSM48_IE_CLIR_INVOC]	= { TLV_TYPE_T },
		[GSM48_IE_REV_C_SETUP]	= { TLV_TYPE_T },
		[GSM48_IE_REPEAT_CIR]   = { TLV_TYPE_T },
		[GSM48_IE_REPEAT_SEQ]   = { TLV_TYPE_T },
		/* FIXME: more elements */
	},
};

static const char *cc_state_names[] = {
	"NULL",
	"INITIATED",
	"illegal state 2",
	"MO_CALL_PROC",
	"CALL_DELIVERED",
	"illegal state 5",
	"CALL_PRESENT",
	"CALL_RECEIVED",
	"CONNECT_REQUEST",
	"MO_TERM_CALL_CONF",
	"ACTIVE",
	"DISCONNECT_REQ",
	"DISCONNECT_IND",
	"illegal state 13",
	"illegal state 14",
	"illegal state 15",
	"illegal state 16",
	"illegal state 17",
	"illegal state 18",
	"RELEASE_REQ",
	"illegal state 20",
	"illegal state 21",
	"illegal state 22",
	"illegal state 23",
	"illegal state 24",
	"illegal state 25",
	"MO_ORIG_MODIFY",
	"MO_TERM_MODIFY",
	"CONNECT_IND",
	"illegal state 29",
	"illegal state 30",
	"illegal state 31",
};


static int mncc_handle_lchan_signal(unsigned int subsys, unsigned int signal,
				    void *handler_data, void *signal_data)
{
	struct gsm_trans *trans, *temp;

	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	struct gsm_lchan *lchan = (struct gsm_lchan *)signal_data;
	if (!lchan)
		return 0;

	/* Free all transactions that are associated with the released lchan */
	llist_for_each_entry_safe(trans, temp, &lchan->ts->trx->bts->network->trans_list, entry) {
		if (trans->lchan == lchan)
			free_trans(trans);
	}


	return 0;
}

/*
 * This will be ran by the linker when loading the DSO. We use it to
 * do system initialization, e.g. registration of signal handlers.
 */
static __attribute__((constructor)) void on_dso_load_mncc(void)
{
	register_signal_handler(SS_LCHAN, mncc_handle_lchan_signal, NULL);
}

/* decode 'bearer capability' */
static int decode_bearer_cap(struct gsm_mncc_bearer_cap *bcap,
			     const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i, s;

	if (in_len < 1)
		return -EINVAL;

	bcap->speech_ver[0] = -1; /* end of list, of maximum 7 values */

	/* octet 3 */
	bcap->transfer = lv[1] & 0x07;
	bcap->mode = (lv[1] & 0x08) >> 3;
	bcap->coding = (lv[1] & 0x10) >> 4;
	bcap->radio = (lv[1] & 0x60) >> 5;

	i = 1;
	s = 0;
	while(!(lv[i] & 0x80)) {
		i++; /* octet 3a etc */
		if (in_len < i)
			return 0;
		bcap->speech_ver[s++] = lv[i] & 0x0f;
		bcap->speech_ver[s] = -1; /* end of list */
		if (i == 2) /* octet 3a */
			bcap->speech_ctm = (lv[i] & 0x20) >> 5;
		if (s == 7) /* maximum speech versions + end of list */
			return 0;
	}

	return 0;
}

/* encode 'bearer capability' */
static int encode_bearer_cap(struct msgb *msg, int lv_only,
			     const struct gsm_mncc_bearer_cap *bcap)
{
	u_int8_t lv[32 + 1];
	int i, s;

	lv[1] = bcap->transfer;
	lv[1] |= bcap->mode << 3;
	lv[1] |= bcap->coding << 4;
	lv[1] |= bcap->radio << 5;

	i = 1;
	for (s = 0; bcap->speech_ver[s] >= 0; s++) {
		i++; /* octet 3a etc */
		lv[i] = bcap->speech_ver[s];
		if (i == 2) /* octet 3a */
			lv[i] |= bcap->speech_ctm << 5;
	}
	lv[i] |= 0x80; /* last IE of octet 3 etc */

	lv[0] = i;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_BEARER_CAP, lv[0], lv+1);

	return 0;
}

/* decode 'call control cap' */
static int decode_cccap(struct gsm_mncc_cccap *ccap, const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	/* octet 3 */
	ccap->dtmf = lv[1] & 0x01;
	ccap->pcp = (lv[1] & 0x02) >> 1;

	return 0;
}

/* decode 'called party BCD number' */
static int decode_called(struct gsm_mncc_number *called,
			 const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	/* octet 3 */
	called->plan = lv[1] & 0x0f;
	called->type = (lv[1] & 0x70) >> 4;

	/* octet 4..N */
	decode_bcd_number(called->number, sizeof(called->number), lv, 1);

	return 0;
}

/* encode 'called party BCD number' */
static int encode_called(struct msgb *msg,
			 const struct gsm_mncc_number *called)
{
	u_int8_t lv[18];
	int ret;

	/* octet 3 */
	lv[1] = called->plan;
	lv[1] |= called->type << 4;

	/* octet 4..N, octet 2 */
	ret = encode_bcd_number(lv, sizeof(lv), 1, called->number);
	if (ret < 0)
		return ret;

	msgb_tlv_put(msg, GSM48_IE_CALLED_BCD, lv[0], lv+1);

	return 0;
}

/* encode callerid of various IEs */
static int encode_callerid(struct msgb *msg, int ie,
			   const struct gsm_mncc_number *callerid)
{
	u_int8_t lv[13];
	int h_len = 1;
	int ret;

	/* octet 3 */
	lv[1] = callerid->plan;
	lv[1] |= callerid->type << 4;

	if (callerid->present || callerid->screen) {
		/* octet 3a */
		lv[2] = callerid->screen;
		lv[2] |= callerid->present << 5;
		lv[2] |= 0x80;
		h_len++;
	} else
		lv[1] |= 0x80;

	/* octet 4..N, octet 2 */
	ret = encode_bcd_number(lv, sizeof(lv), h_len, callerid->number);
	if (ret < 0)
		return ret;

	msgb_tlv_put(msg, ie, lv[0], lv+1);

	return 0;
}

/* decode 'cause' */
static int decode_cause(struct gsm_mncc_cause *cause,
			const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i;

	if (in_len < 2)
		return -EINVAL;

	cause->diag_len = 0;

	/* octet 3 */
	cause->location = lv[1] & 0x0f;
	cause->coding = (lv[1] & 0x60) >> 5;

	i = 1;
	if (!(lv[i] & 0x80)) {
		i++; /* octet 3a */
		if (in_len < i+1)
			return 0;
		cause->rec = 1;
		cause->rec_val = lv[i] & 0x7f;

	}
	i++;

	/* octet 4 */
	cause->value = lv[i] & 0x7f;
	i++;

	if (in_len < i) /* no diag */
		return 0;

	if (in_len - (i-1) > 32) /* maximum 32 octets */
		return 0;

	/* octet 5-N */
	memcpy(cause->diag, lv + i, in_len - (i-1));
	cause->diag_len = in_len - (i-1);

	return 0;
}

/* encode 'cause' */
static int encode_cause(struct msgb *msg, int lv_only,
			const struct gsm_mncc_cause *cause)
{
	u_int8_t lv[32+4];
	int i;

	if (cause->diag_len > 32)
		return -EINVAL;

	/* octet 3 */
	lv[1] = cause->location;
	lv[1] |= cause->coding << 5;

	i = 1;
	if (cause->rec) {
		i++; /* octet 3a */
		lv[i] = cause->rec_val;
	}
	lv[i] |= 0x80; /* end of octet 3 */

	/* octet 4 */
	i++;
	lv[i] = 0x80 | cause->value;

	/* octet 5-N */
	if (cause->diag_len) {
		memcpy(lv + i, cause->diag, cause->diag_len);
		i += cause->diag_len;
	}

	lv[0] = i;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_CAUSE, lv[0], lv+1);

	return 0;
}

/* encode 'calling number' */
static int encode_calling(struct msgb *msg,
			  const struct gsm_mncc_number *calling)
{
	return encode_callerid(msg, GSM48_IE_CALLING_BCD, calling);
}

/* encode 'connected number' */
static int encode_connected(struct msgb *msg,
			    const struct gsm_mncc_number *connected)
{
	return encode_callerid(msg, GSM48_IE_CONN_BCD, connected);
}

/* encode 'redirecting number' */
static int encode_redirecting(struct msgb *msg,
			      const struct gsm_mncc_number *redirecting)
{
	return encode_callerid(msg, GSM48_IE_REDIR_BCD, redirecting);
}

/* decode 'facility' */
static int decode_facility(struct gsm_mncc_facility *facility,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	if (in_len > sizeof(facility->info))
		return -EINVAL;

	memcpy(facility->info, lv+1, in_len);
	facility->len = in_len;

	return 0;
}

/* encode 'facility' */
static int encode_facility(struct msgb *msg, int lv_only,
			   const struct gsm_mncc_facility *facility)
{
	u_int8_t lv[GSM_MAX_FACILITY + 1];

	if (facility->len < 1 || facility->len > GSM_MAX_FACILITY)
		return -EINVAL;

	memcpy(lv+1, facility->info, facility->len);
	lv[0] = facility->len;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_FACILITY, lv[0], lv+1);

	return 0;
}

/* decode 'notify' */
static int decode_notify(int *notify, const u_int8_t *v)
{
	*notify = v[0] & 0x7f;

	return 0;
}

/* encode 'notify' */
static int encode_notify(struct msgb *msg, int notify)
{
	msgb_v_put(msg, notify | 0x80);

	return 0;
}

/* encode 'signal' */
static int encode_signal(struct msgb *msg, int signal)
{
	msgb_tv_put(msg, GSM48_IE_SIGNAL, signal);

	return 0;
}

/* decode 'keypad' */
static int decode_keypad(int *keypad, const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	*keypad = lv[1] & 0x7f;

	return 0;
}

/* encode 'keypad' */
static int encode_keypad(struct msgb *msg, int keypad)
{
	msgb_tv_put(msg, GSM48_IE_KPD_FACILITY, keypad);

	return 0;
}

/* decode 'progress' */
static int decode_progress(struct gsm_mncc_progress *progress,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 2)
		return -EINVAL;

	progress->coding = (lv[1] & 0x60) >> 5;
	progress->location = lv[1] & 0x0f;
	progress->descr = lv[2] & 0x7f;

	return 0;
}

/* encode 'progress' */
static int encode_progress(struct msgb *msg, int lv_only,
			   const struct gsm_mncc_progress *p)
{
	u_int8_t lv[3];

	lv[0] = 2;
	lv[1] = 0x80 | ((p->coding & 0x3) << 5) | (p->location & 0xf);
	lv[2] = 0x80 | (p->descr & 0x7f);
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_PROGR_IND, lv[0], lv+1);

	return 0;
}

/* decode 'user-user' */
static int decode_useruser(struct gsm_mncc_useruser *uu,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	char *info = uu->info;
	int info_len = sizeof(uu->info);
	int i;

	if (in_len < 1)
		return -EINVAL;

	uu->proto = lv[1];

	for (i = 2; i <= in_len; i++) {
		info_len--;
		if (info_len <= 1)
			break;
		*info++ = lv[i];
	}
	if (info_len >= 1)
		*info++ = '\0';

	return 0;
}

/* encode 'useruser' */
static int encode_useruser(struct msgb *msg, int lv_only,
			   const struct gsm_mncc_useruser *uu)
{
	u_int8_t lv[GSM_MAX_USERUSER + 2];

	if (strlen(uu->info) > GSM_MAX_USERUSER)
		return -EINVAL;

	lv[0] = 1 + strlen(uu->info);
	lv[1] = uu->proto;
	memcpy(lv + 2, uu->info, strlen(uu->info));
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_USER_USER, lv[0], lv+1);

	return 0;
}

/* decode 'ss version' */
static int decode_ssversion(struct gsm_mncc_ssversion *ssv,
			    const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1 || in_len < sizeof(ssv->info))
		return -EINVAL;

	memcpy(ssv->info, lv + 1, in_len);
	ssv->len = in_len;

	return 0;
}

/* encode 'more data' */
static int encode_more(struct msgb *msg)
{
	u_int8_t *ie;

	ie = msgb_put(msg, 1);
	ie[0] = GSM48_IE_MORE_DATA;

	return 0;
}

#define DECLARE_DECODER3(IE_NAME, M_NAME, name) \
	[_MNCC_E_##M_NAME] = \
	{ .information_element = GSM48_IE_##IE_NAME, \
	  .mncc_field = MNCC_F_##M_NAME, \
	  .offset = offsetof(struct gsm_mncc, name), \
	  .decoder = (dd_decoder)decode_##name, \
	}

#define DECLARE_DECODER(NAME, name) \
	    DECLARE_DECODER3(NAME, NAME, name)

typedef int (*dd_decoder)(void* data, const u_int8_t *lv);

struct dd_parser {
	int information_element;
	int mncc_field;
	int offset;
	dd_decoder decoder;
};

static const struct dd_parser dd_parsers [_MNCC_E_LAST_ITEM] = {
	DECLARE_DECODER(CAUSE, cause),
	DECLARE_DECODER(FACILITY, facility),
	DECLARE_DECODER3(USER_USER, USERUSER, useruser),
	DECLARE_DECODER3(SS_VERS, SSVERSION, ssversion),
	DECLARE_DECODER3(KPD_FACILITY, KEYPAD, keypad),
	DECLARE_DECODER(BEARER_CAP, bearer_cap),
	DECLARE_DECODER3(CALLED_BCD, CALLED, called),
	DECLARE_DECODER3(CC_CAP, CCCAP, cccap),
	DECLARE_DECODER3(PROGR_IND, PROGRESS, progress),
};

static void parse_data_derived_information(struct tlv_parsed *tp, struct gsm_mncc *rel, int flags)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dd_parsers); ++i) {
		if ((flags & (1<<i)) == (1<<i) &&
		     TLVP_PRESENT(tp, dd_parsers[i].information_element) &&
		     dd_parsers[i].decoder) {

			rel->fields |= dd_parsers[i].mncc_field;
			dd_parsers[i].decoder(rel + dd_parsers[i].offset,
					      TLVP_VAL(tp, dd_parsers[i].information_element)-1);
		}
	}
}


/* map two ipaccess RTP streams onto each other */
static int tch_map(struct gsm_lchan *lchan, struct gsm_lchan *remote_lchan)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_bts *remote_bts = remote_lchan->ts->trx->bts;
	struct gsm_bts_trx_ts *ts;

	DEBUGP(DCC, "Setting up TCH map between (bts=%u,trx=%u,ts=%u) and (bts=%u,trx=%u,ts=%u)\n",
		bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		remote_bts->nr, remote_lchan->ts->trx->nr, remote_lchan->ts->nr);

	if (bts->type != remote_bts->type) {
		DEBUGP(DCC, "Cannot switch calls between different BTS types yet\n");
		return -EINVAL;
	}

	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS_900:
	case GSM_BTS_TYPE_NANOBTS_1800:
		ts = remote_lchan->ts;
		rsl_ipacc_connect(lchan, ts->abis_ip.bound_ip, ts->abis_ip.bound_port,
				  lchan->ts->abis_ip.attr_f8, ts->abis_ip.attr_fc);

		ts = lchan->ts;
		rsl_ipacc_connect(remote_lchan, ts->abis_ip.bound_ip, ts->abis_ip.bound_port,
				  remote_lchan->ts->abis_ip.attr_f8, ts->abis_ip.attr_fc);
		break;
	case GSM_BTS_TYPE_BS11:
		trau_mux_map_lchan(lchan, remote_lchan);
		break;
	default:
		DEBUGP(DCC, "Unknown BTS type %u\n", bts->type);
		break;
	}

	return 0;
}

static struct gsm_trans *get_trans_ref(struct gsm_network *net, u_int32_t callref)
{
	struct gsm_trans *trans;
	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->callref == callref)
			return trans;
	}
	return NULL;
}

/* bridge channels of two transactions */
static int tch_bridge(struct gsm_network *net, u_int32_t *refs)
{
	struct gsm_trans *trans1 = get_trans_ref(net, refs[0]);
	struct gsm_trans *trans2 = get_trans_ref(net, refs[1]);

	if (!trans1 || !trans2)
		return -EIO;

	if (!trans1->lchan || !trans2->lchan)
		return -EIO;

	/* through-connect channel */
	return tch_map(trans1->lchan, trans2->lchan);
}

/* enable receive of channels to upqueue */
static int tch_recv(struct gsm_network *net, struct gsm_mncc *data, int enable)
{
	struct gsm_trans *trans;

	/* Find callref */
	trans = get_trans_ref(net, data->callref);
	if (!trans)
		return -EIO;
	if (!trans->lchan)
		return 0;

	// todo IPACCESS
	if (enable)
		return trau_recv_lchan(trans->lchan, data->callref);
	return trau_mux_unmap(NULL, data->callref);
}

/* send a frame to channel */
static int tch_frame(struct gsm_network *net, struct gsm_trau_frame *frame)
{
	struct gsm_trans *trans;

	/* Find callref */
	trans = get_trans_ref(net, frame->callref);
	if (!trans)
		return -EIO;
	if (!trans->lchan)
		return 0;
	if (trans->lchan->type != GSM_LCHAN_TCH_F &&
	    trans->lchan->type != GSM_LCHAN_TCH_H)
		return 0;

	// todo IPACCESS
	return trau_send_lchan(trans->lchan,
				(struct decoded_trau_frame *)frame->data);
}

/* call-back from paging the B-end of the connection */
static int setup_trig_pag_evt(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_lchan, void *param)
{
	struct gsm_lchan *lchan = _lchan;
	struct gsm_subscriber *subscr = param;
	struct gsm_trans *transt, *tmp;
	struct gsm_network *net;

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	if (!subscr)
		return -EINVAL;
	net = subscr->net;
	if (!net) {
		DEBUGP(DCC, "Error Network not set!\n");
		return -EINVAL;
	}

	/* check all tranactions (without lchan) for subscriber */
	llist_for_each_entry_safe(transt, tmp, &net->trans_list, entry) {
		if (transt->subscr != subscr || transt->lchan)
			continue;
		switch (event) {
		case GSM_PAGING_SUCCEEDED:
			if (!lchan) // paranoid
				break;
			DEBUGP(DCC, "Paging subscr %s succeeded!\n",
				subscr->extension);
			/* Assign lchan */
			if (!transt->lchan) {
				transt->lchan = lchan;
				use_lchan(lchan);
			}
			/* send SETUP request to called party */
			msc_cc_tx_setup(transt, &transt->cc_msg);
			if (is_ipaccess_bts(lchan->ts->trx->bts))
				rsl_ipacc_bind(lchan);
			break;
		case GSM_PAGING_EXPIRED:
			DEBUGP(DCC, "Paging subscr %s expired!\n",
				subscr->extension);
			/* Temporarily out of order */
			mncc_release_ind(transt->network, transt, transt->callref,
					 GSM48_CAUSE_LOC_PRN_S_LU,
					 GSM48_CC_CAUSE_DEST_OOO);
			transt->callref = 0;
			free_trans(transt);
			break;
		}
	}
	return 0;
}


/* Call Control */

/* The entire call control code is written in accordance with Figure 7.10c
 * for 'very early assignment', i.e. we allocate a TCH/F during IMMEDIATE
 * ASSIGN, then first use that TCH/F for signalling and later MODE MODIFY
 * it for voice */

static void new_cc_state(struct gsm_trans *trans, int state)
{
	if (state > 31 || state < 0)
		return;

	DEBUGP(DCC, "new state %s -> %s\n",
		cc_state_names[trans->state], cc_state_names[state]);

	trans->state = state;
}

static void msc_stop_cc_timer(struct gsm_trans *trans)
{
	if (bsc_timer_pending(&trans->cc_timer)) {
		DEBUGP(DCC, "stopping pending timer T%x\n", trans->Tcurrent);
		bsc_del_timer(&trans->cc_timer);
		trans->Tcurrent = 0;
	}
}

static int mncc_recvmsg(struct gsm_network *net, struct gsm_trans *trans,
			int msg_type, struct gsm_mncc *mncc)
{
	struct msgb *msg;

	if (trans)
		if (trans->lchan)
			DEBUGP(DCC, "(bts %d trx %d ts %d ti %02x sub %s) "
				"Sending '%s' to MNCC.\n",
				trans->lchan->ts->trx->bts->nr,
				trans->lchan->ts->trx->nr,
				trans->lchan->ts->nr, trans->transaction_id,
				(trans->subscr)?(trans->subscr->extension):"-",
				get_mncc_name(msg_type));
		else
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Sending '%s' to MNCC.\n",
				(trans->subscr)?(trans->subscr->extension):"-",
				get_mncc_name(msg_type));
	else
		DEBUGP(DCC, "(bts - trx - ts - ti -- sub -) "
			"Sending '%s' to MNCC.\n", get_mncc_name(msg_type));

	mncc->msg_type = msg_type;

	msg = msgb_alloc(sizeof(struct gsm_mncc), "MNCC");
	if (!msg)
		return -ENOMEM;
	memcpy(msg->data, mncc, sizeof(struct gsm_mncc));
	msgb_enqueue(&net->upqueue, msg);

	return 0;
}

int mncc_release_ind(struct gsm_network *net, struct gsm_trans *trans,
		     u_int32_t callref, int location, int value)
{
	struct gsm_mncc rel;

	memset(&rel, 0, sizeof(rel));
	rel.callref = callref;
	mncc_set_cause(&rel, location, value);
	return mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
}

static void free_trans(struct gsm_trans *trans)
{
	struct gsm_bts *bts;

	msc_stop_cc_timer(trans);

	/* send release to L4, if callref still exists */
	if (trans->callref) {
		/* Ressource unavailable */
		mncc_release_ind(trans->network, trans, trans->callref,
				 GSM48_CAUSE_LOC_PRN_S_LU,
				 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		if (trans->state != GSM_CSTATE_NULL)
			new_cc_state(trans, GSM_CSTATE_NULL);
	}

	if (!trans->lchan && trans->subscr && trans->subscr->net) {
		/* Stop paging on all bts' */
		bts = NULL;
		do {
			bts = gsm_bts_by_lac(trans->subscr->net,
					     trans->subscr->lac, bts);
			if (!bts)
				break;
			/* Stop paging */
			paging_request_stop(bts, trans->subscr, NULL);
		} while (1);
	}

	if (trans->lchan) {
		trau_mux_unmap(&trans->lchan->ts->e1_link, trans->callref);
		put_lchan(trans->lchan);
	}

	if (trans->subscr)
		subscr_put(trans->subscr);

	if (trans->state != GSM_CSTATE_NULL)
		new_cc_state(trans, GSM_CSTATE_NULL);

	llist_del(&trans->entry);

	talloc_free(trans);
}



static int msc_cc_tx_status(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause, *call_state;

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_STATUS;

	cause = msgb_put(msg, 3);
	cause[0] = 2;
	cause[1] = GSM48_CAUSE_CS_GSM | GSM48_CAUSE_LOC_USER;
	cause[2] = 0x80 | 30;	/* response to status inquiry */

	call_state = msgb_put(msg, 1);
	call_state[0] = 0xc0 | 0x00;

	return gsm48_sendmsg(msg);
}


static int msc_cc_rx_status_enq(struct gsm_trans *trans, struct msgb *msg)
{
	DEBUGP(DCC, "-> STATUS ENQ\n");
	return msc_cc_tx_status(trans, msg);
}

static int msc_cc_tx_release(struct gsm_trans *trans, void *arg);
static int msc_cc_tx_disconnect(struct gsm_trans *trans, void *arg);

static void msc_cc_timeout(void *arg)
{
	struct gsm_trans *trans = arg;
	int disconnect = 0, release = 0;
	int mo_cause = GSM48_CC_CAUSE_RECOVERY_TIMER;
	int mo_location = GSM48_CAUSE_LOC_USER;
	int l4_cause = GSM48_CC_CAUSE_NORMAL_UNSPEC;
	int l4_location = GSM48_CAUSE_LOC_PRN_S_LU;
	struct gsm_mncc mo_rel, l4_rel;

	memset(&mo_rel, 0, sizeof(struct gsm_mncc));
	mo_rel.callref = trans->callref;
	memset(&l4_rel, 0, sizeof(struct gsm_mncc));
	l4_rel.callref = trans->callref;

	switch(trans->Tcurrent) {
	case 0x303:
		release = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x310:
		disconnect = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x313:
		disconnect = 1;
		/* unknown, did not find it in the specs */
		break;
	case 0x301:
		disconnect = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x308:
		if (!trans->T308_second) {
			/* restart T308 a second time */
			msc_cc_tx_release(trans, &trans->cc_msg);
			trans->T308_second = 1;
			break; /* stay in release state */
		}
		free_trans(trans);
		return;
//		release = 1;
//		l4_cause = 14;
//		break;
	case 0x306:
		release = 1;
		mo_cause = trans->cc_msg.cause.value;
		mo_location = trans->cc_msg.cause.location;
		break;
	case 0x323:
		disconnect = 1;
		break;
	default:
		release = 1;
	}

	if (release && trans->callref) {
		/* process release towards layer 4 */
		mncc_release_ind(trans->network, trans, trans->callref,
				 l4_location, l4_cause);
		trans->callref = 0;
	}

	if (disconnect && trans->callref) {
		/* process disconnect towards layer 4 */
		mncc_set_cause(&l4_rel, l4_location, l4_cause);
		mncc_recvmsg(trans->network, trans, MNCC_DISC_IND, &l4_rel);
	}

	/* process disconnect towards mobile station */
	if (disconnect || release) {
		mncc_set_cause(&mo_rel, mo_location, mo_cause);
		mo_rel.cause.diag[0] = ((trans->Tcurrent & 0xf00) >> 8) + '0';
		mo_rel.cause.diag[1] = ((trans->Tcurrent & 0x0f0) >> 4) + '0';
		mo_rel.cause.diag[2] = (trans->Tcurrent & 0x00f) + '0';
		mo_rel.cause.diag_len = 3;

		if (disconnect)
			msc_cc_tx_disconnect(trans, &mo_rel);
		if (release)
			msc_cc_tx_release(trans, &mo_rel);
	}

}

static void msc_start_cc_timer(struct gsm_trans *trans, int current,
				 int sec, int micro)
{
	DEBUGP(DCC, "starting timer T%x with %d seconds\n", current, sec);
	trans->cc_timer.cb = msc_cc_timeout;
	trans->cc_timer.data = trans;
	bsc_schedule_timer(&trans->cc_timer, sec, micro);
	trans->Tcurrent = current;
}

static int msc_cc_rx_setup(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type & 0xbf;
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc setup;

	memset(&setup, 0, sizeof(struct gsm_mncc));
	setup.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* emergency setup is identified by msg_type */
	if (msg_type == GSM48_MT_CC_EMERG_SETUP)
		setup.emergency = 1;

	/* use subscriber as calling party number */
	if (trans->subscr) {
		setup.fields |= MNCC_F_CALLING;
		strncpy(setup.calling.number, trans->subscr->extension,
			sizeof(setup.calling.number)-1);
		strncpy(setup.imsi, trans->subscr->imsi,
			sizeof(setup.imsi)-1);
	}

	parse_data_derived_information(&tp, &setup, MNCC_F_BEARER_CAP | MNCC_F_FACILITY |
				       MNCC_F_CALLED | MNCC_F_USERUSER |
				       MNCC_F_SSVERSION | MNCC_F_CCCAP);

	/* CLIR suppression */
	if (TLVP_PRESENT(&tp, GSM48_IE_CLIR_SUPP))
		setup.clir.sup = 1;
	/* CLIR invocation */
	if (TLVP_PRESENT(&tp, GSM48_IE_CLIR_INVOC))
		setup.clir.inv = 1;

	if (is_ipaccess_bts(msg->trx->bts))
		rsl_ipacc_bind(msg->lchan);

	new_cc_state(trans, GSM_CSTATE_INITIATED);

	/* indicate setup to MNCC */
	mncc_recvmsg(trans->network, trans, MNCC_SETUP_IND, &setup);

	return 0;
}

static int msc_cc_tx_setup(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_mncc *setup = arg;
	struct gsm_trans *transt;
	u_int16_t trans_id_mask = 0;
	int rc, i;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	/* transaction id must not be assigned */
	if (trans->transaction_id != 0xff) { /* unasssigned */
		DEBUGP(DCC, "TX Setup with assigned transaction. "
			"This is not allowed!\n");
		/* Temporarily out of order */
		rc = mncc_release_ind(trans->network, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		free_trans(trans);
		return rc;
	}

	/* Get free transaction_id */
	llist_for_each_entry(transt, &trans->network->trans_list, entry) {
		/* Transaction of our lchan? */
		if (transt->lchan == trans->lchan &&
		    transt->transaction_id != 0xff)
			trans_id_mask |= (1 << (transt->transaction_id >> 4));
	}
	/* Assign free transaction ID */
	if ((trans_id_mask & 0x007f) == 0x7f) {
		/* no free transaction ID */
		rc = mncc_release_ind(trans->network, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		free_trans(trans);
		return rc;
	}
	for (i = 0; i < 7; i++) {
		if ((trans_id_mask & (1 << i)) == 0) {
			trans->transaction_id = i << 4; /* flag = 0 */
			break;
		}
	}

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_SETUP;

	msc_start_cc_timer(trans, 0x303, GSM48_T303);

	/* bearer capability */
	if (setup->fields & MNCC_F_BEARER_CAP)
		encode_bearer_cap(msg, 0, &setup->bearer_cap);
	/* facility */
	if (setup->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &setup->facility);
	/* progress */
	if (setup->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &setup->progress);
	/* calling party BCD number */
	if (setup->fields & MNCC_F_CALLING)
		encode_calling(msg, &setup->calling);
	/* called party BCD number */
	if (setup->fields & MNCC_F_CALLED)
		encode_called(msg, &setup->called);
	/* user-user */
	if (setup->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &setup->useruser);
	/* redirecting party BCD number */
	if (setup->fields & MNCC_F_REDIRECTING)
		encode_redirecting(msg, &setup->redirecting);
	/* signal */
	if (setup->fields & MNCC_F_SIGNAL)
		encode_signal(msg, setup->signal);

	new_cc_state(trans, GSM_CSTATE_CALL_PRESENT);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_call_conf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc call_conf;

	msc_stop_cc_timer(trans);
	msc_start_cc_timer(trans, 0x310, GSM48_T310);

	memset(&call_conf, 0, sizeof(struct gsm_mncc));
	call_conf.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
#if 0
	/* repeat */
	if (TLVP_PRESENT(&tp, GSM48_IE_REPEAT_CIR))
		call_conf.repeat = 1;
	if (TLVP_PRESENT(&tp, GSM48_IE_REPEAT_SEQ))
		call_conf.repeat = 2;
#endif

	parse_data_derived_information(&tp, &call_conf, MNCC_F_BEARER_CAP |
				       MNCC_F_CAUSE | MNCC_F_CCCAP);

	new_cc_state(trans, GSM_CSTATE_MO_TERM_CALL_CONF);

	return mncc_recvmsg(trans->network, trans, MNCC_CALL_CONF_IND, &call_conf);
}

static int msc_cc_tx_call_proc(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *proceeding = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_CALL_PROC;

	new_cc_state(trans, GSM_CSTATE_MO_CALL_PROC);

	/* bearer capability */
	if (proceeding->fields & MNCC_F_BEARER_CAP)
		encode_bearer_cap(msg, 0, &proceeding->bearer_cap);
	/* facility */
	if (proceeding->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &proceeding->facility);
	/* progress */
	if (proceeding->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &proceeding->progress);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_alerting(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc alerting;

	msc_stop_cc_timer(trans);
	msc_start_cc_timer(trans, 0x301, GSM48_T301);

	memset(&alerting, 0, sizeof(struct gsm_mncc));
	alerting.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	parse_data_derived_information(&tp, &alerting, MNCC_F_FACILITY |
				      MNCC_F_PROGRESS | MNCC_F_SSVERSION);

	new_cc_state(trans, GSM_CSTATE_CALL_RECEIVED);

	return mncc_recvmsg(trans->network, trans, MNCC_ALERT_IND, &alerting);
}

static int msc_cc_tx_alerting(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *alerting = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_ALERTING;

	/* facility */
	if (alerting->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &alerting->facility);
	/* progress */
	if (alerting->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &alerting->progress);
	/* user-user */
	if (alerting->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &alerting->useruser);

	new_cc_state(trans, GSM_CSTATE_CALL_DELIVERED);

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_progress(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *progress = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_PROGRESS;

	/* progress */
	encode_progress(msg, 1, &progress->progress);
	/* user-user */
	if (progress->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &progress->useruser);

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_connect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *connect = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_CONNECT;

	msc_stop_cc_timer(trans);
	msc_start_cc_timer(trans, 0x313, GSM48_T313);

	/* facility */
	if (connect->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &connect->facility);
	/* progress */
	if (connect->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &connect->progress);
	/* connected number */
	if (connect->fields & MNCC_F_CONNECTED)
		encode_connected(msg, &connect->connected);
	/* user-user */
	if (connect->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &connect->useruser);

	new_cc_state(trans, GSM_CSTATE_CONNECT_IND);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_connect(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc connect;

	msc_stop_cc_timer(trans);

	memset(&connect, 0, sizeof(struct gsm_mncc));
	connect.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* use subscriber as connected party number */
	if (trans->subscr) {
		connect.fields |= MNCC_F_CONNECTED;
		strncpy(connect.connected.number, trans->subscr->extension,
			sizeof(connect.connected.number)-1);
		strncpy(connect.imsi, trans->subscr->imsi,
			sizeof(connect.imsi)-1);
	}

	parse_data_derived_information(&tp, &connect, MNCC_F_FACILITY |
				       MNCC_F_USERUSER | MNCC_F_SSVERSION);
	new_cc_state(trans, GSM_CSTATE_CONNECT_REQUEST);

	return mncc_recvmsg(trans->network, trans, MNCC_SETUP_CNF, &connect);
}


static int msc_cc_rx_connect_ack(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc connect_ack;

	msc_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = trans->callref;
	return mncc_recvmsg(trans->network, trans, MNCC_SETUP_COMPL_IND,
			    &connect_ack);
}

static int msc_cc_tx_connect_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_CONNECT_ACK;

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_disconnect(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc disc;

	msc_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_REQ);

	memset(&disc, 0, sizeof(struct gsm_mncc));
	disc.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_CAUSE, 0);
	parse_data_derived_information(&tp, &disc, MNCC_F_CAUSE |
				       MNCC_F_FACILITY | MNCC_F_USERUSER |
				       MNCC_F_SSVERSION);
	return mncc_recvmsg(trans->network, trans, MNCC_DISC_IND, &disc);

}

static struct gsm_mncc_cause default_cause = {
	.location	= GSM48_CAUSE_LOC_PRN_S_LU,
	.coding		= 0,
	.rec		= 0,
	.rec_val	= 0,
	.value		= GSM48_CC_CAUSE_NORMAL_UNSPEC,
	.diag_len	= 0,
	.diag		= { 0 },
};

static int msc_cc_tx_disconnect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *disc = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_DISCONNECT;

	msc_stop_cc_timer(trans);
	msc_start_cc_timer(trans, 0x306, GSM48_T306);

	/* cause */
	if (disc->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &disc->cause);
	else
		encode_cause(msg, 1, &default_cause);

	/* facility */
	if (disc->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &disc->facility);
	/* progress */
	if (disc->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &disc->progress);
	/* user-user */
	if (disc->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &disc->useruser);

	/* store disconnect cause for T306 expiry */
	memcpy(&trans->cc_msg, disc, sizeof(struct gsm_mncc));

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_IND);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_release(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc rel;
	int rc;

	msc_stop_cc_timer(trans);

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	parse_data_derived_information(&tp, &rel, MNCC_F_CAUSE | MNCC_F_FACILITY |
				       MNCC_F_USERUSER | MNCC_F_SSVERSION);

	if (trans->state == GSM_CSTATE_RELEASE_REQ) {
		/* release collision 5.4.5 */
		rc = mncc_recvmsg(trans->network, trans, MNCC_REL_CNF, &rel);
	} else {
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC | trans->transaction_id,
			     GSM48_MT_CC_RELEASE_COMPL);
		rc = mncc_recvmsg(trans->network, trans, MNCC_REL_IND, &rel);
	}

	new_cc_state(trans, GSM_CSTATE_NULL);

	trans->callref = 0;
	free_trans(trans);

	return rc;
}

static int msc_cc_tx_release(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_RELEASE;

	trans->callref = 0;

	msc_stop_cc_timer(trans);
	msc_start_cc_timer(trans, 0x308, GSM48_T308);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &rel->useruser);

	trans->T308_second = 0;
	memcpy(&trans->cc_msg, rel, sizeof(struct gsm_mncc));

	if (trans->state != GSM_CSTATE_RELEASE_REQ)
		new_cc_state(trans, GSM_CSTATE_RELEASE_REQ);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_release_compl(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc rel;
	int rc = 0;

	msc_stop_cc_timer(trans);

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	parse_data_derived_information(&tp, &rel, MNCC_F_CAUSE | MNCC_F_FACILITY |
				       MNCC_F_USERUSER | MNCC_F_SSVERSION);

	if (trans->callref) {
		switch (trans->state) {
		case GSM_CSTATE_CALL_PRESENT:
			rc = mncc_recvmsg(trans->network, trans,
					  MNCC_REJ_IND, &rel);
			break;
		case GSM_CSTATE_RELEASE_REQ:
			rc = mncc_recvmsg(trans->network, trans,
					  MNCC_REL_CNF, &rel);
			break;
		default:
			rc = mncc_recvmsg(trans->network, trans,
					  MNCC_REL_IND, &rel);
		}
	}

	trans->callref = 0;
	free_trans(trans);

	return rc;
}

static int msc_cc_tx_release_compl(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_RELEASE_COMPL;

	trans->callref = 0;

	msc_stop_cc_timer(trans);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &rel->useruser);

	free_trans(trans);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_facility(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc fac;

	memset(&fac, 0, sizeof(struct gsm_mncc));
	fac.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_FACILITY, 0);
	parse_data_derived_information(&tp, &fac, MNCC_F_FACILITY | MNCC_F_SSVERSION);
	return mncc_recvmsg(trans->network, trans, MNCC_FACILITY_IND, &fac);
}

static int msc_cc_tx_facility(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *fac = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_FACILITY;

	/* facility */
	encode_facility(msg, 1, &fac->facility);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_hold(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc hold;

	memset(&hold, 0, sizeof(struct gsm_mncc));
	hold.callref = trans->callref;
	return mncc_recvmsg(trans->network, trans, MNCC_HOLD_IND, &hold);
}

static int msc_cc_tx_hold_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_HOLD_ACK;

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_hold_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *hold_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_HOLD_REJ;

	/* cause */
	if (hold_rej->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &hold_rej->cause);
	else
		encode_cause(msg, 1, &default_cause);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_retrieve(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc retrieve;

	memset(&retrieve, 0, sizeof(struct gsm_mncc));
	retrieve.callref = trans->callref;
	return mncc_recvmsg(trans->network, trans, MNCC_RETRIEVE_IND, &retrieve);
}

static int msc_cc_tx_retrieve_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_RETR_ACK;

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_retrieve_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *retrieve_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_RETR_REJ;

	/* cause */
	if (retrieve_rej->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &retrieve_rej->cause);
	else
		encode_cause(msg, 1, &default_cause);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_start_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	parse_data_derived_information(&tp, &dtmf, MNCC_F_KEYPAD);
	return mncc_recvmsg(trans->network, trans, MNCC_START_DTMF_IND, &dtmf);
}

static int msc_cc_tx_start_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_START_DTMF_ACK;

	/* keypad */
	if (dtmf->fields & MNCC_F_KEYPAD)
		encode_keypad(msg, dtmf->keypad);

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_start_dtmf_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_START_DTMF_REJ;

	/* cause */
	if (dtmf->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &dtmf->cause);
	else
		encode_cause(msg, 1, &default_cause);

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_stop_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_STOP_DTMF_ACK;

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_stop_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;

	return mncc_recvmsg(trans->network, trans, MNCC_STOP_DTMF_IND, &dtmf);
}

static int msc_cc_rx_modify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	parse_data_derived_information(&tp, &modify, MNCC_F_BEARER_CAP);
	new_cc_state(trans, GSM_CSTATE_MO_ORIG_MODIFY);
	return mncc_recvmsg(trans->network, trans, MNCC_MODIFY_IND, &modify);
}

static int msc_cc_tx_modify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_MODIFY;

	msc_start_cc_timer(trans, 0x323, GSM48_T323);

	/* bearer capability */
	encode_bearer_cap(msg, 1, &modify->bearer_cap);

	new_cc_state(trans, GSM_CSTATE_MO_TERM_MODIFY);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_modify_complete(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	msc_stop_cc_timer(trans);

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	parse_data_derived_information(&tp, &modify, MNCC_F_BEARER_CAP);
	new_cc_state(trans, GSM_CSTATE_ACTIVE);
	return mncc_recvmsg(trans->network, trans, MNCC_MODIFY_CNF, &modify);
}

static int msc_cc_tx_modify_complete(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_MODIFY_COMPL;

	/* bearer capability */
	encode_bearer_cap(msg, 1, &modify->bearer_cap);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_modify_reject(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	msc_stop_cc_timer(trans);

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, GSM48_IE_CAUSE);
	parse_data_derived_information(&tp, &modify, MNCC_F_BEARER_CAP | MNCC_F_CAUSE);
	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->network, trans, MNCC_MODIFY_REJ, &modify);
}

static int msc_cc_tx_modify_reject(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_MODIFY_REJECT;

	/* bearer capability */
	encode_bearer_cap(msg, 1, &modify->bearer_cap);
	/* cause */
	encode_cause(msg, 1, &modify->cause);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_sendmsg(msg);
}

static int msc_cc_tx_notify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *notify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_NOTIFY;

	/* notify */
	encode_notify(msg, notify->notify);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_notify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
//	struct tlv_parsed tp;
	struct gsm_mncc notify;

	memset(&notify, 0, sizeof(struct gsm_mncc));
	notify.callref = trans->callref;
//	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len);
	if (payload_len >= 1)
		decode_notify(&notify.notify, gh->data);

	return mncc_recvmsg(trans->network, trans, MNCC_NOTIFY_IND, &notify);
}

static int msc_cc_tx_userinfo(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *user = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_CC | trans->transaction_id;
	msg->lchan = trans->lchan;
	gh->msg_type = GSM48_MT_CC_USER_INFO;

	/* user-user */
	if (user->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 1, &user->useruser);
	/* more data */
	if (user->more)
		encode_more(msg);

	return gsm48_sendmsg(msg);
}

static int msc_cc_rx_userinfo(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc user;

	memset(&user, 0, sizeof(struct gsm_mncc));
	user.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_USER_USER, 0);
	parse_data_derived_information(&tp, &user, MNCC_F_USERUSER);

	/* more data */
	if (TLVP_PRESENT(&tp, GSM48_IE_MORE_DATA))
		user.more = 1;

	return mncc_recvmsg(trans->network, trans, MNCC_USERINFO_IND, &user);
}

static int msc_cc_lchan_modify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *mode = arg;

	return gsm48_tx_chan_mode_modify(trans->lchan, mode->lchan_mode);
}

static struct downstate {
	u_int32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, void *arg);
} downstatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_INITIATED), /* 5.2.1.2 */
	 MNCC_CALL_PROC_REQ, msc_cc_tx_call_proc},
	{SBIT(GSM_CSTATE_INITIATED) | SBIT(GSM_CSTATE_MO_CALL_PROC), /* 5.2.1.2 | 5.2.1.5 */
	 MNCC_ALERT_REQ, msc_cc_tx_alerting},
	{SBIT(GSM_CSTATE_INITIATED) | SBIT(GSM_CSTATE_MO_CALL_PROC) | SBIT(GSM_CSTATE_CALL_DELIVERED), /* 5.2.1.2 | 5.2.1.6 | 5.2.1.6 */
	 MNCC_SETUP_RSP, msc_cc_tx_connect},
	{SBIT(GSM_CSTATE_MO_CALL_PROC), /* 5.2.1.4.2 */
	 MNCC_PROGRESS_REQ, msc_cc_tx_progress},
	/* mobile terminating call establishment */
	{SBIT(GSM_CSTATE_NULL), /* 5.2.2.1 */
	 MNCC_SETUP_REQ, msc_cc_tx_setup},
	{SBIT(GSM_CSTATE_CONNECT_REQUEST),
	 MNCC_SETUP_COMPL_REQ, msc_cc_tx_connect_ack},
	 /* signalling during call */
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_NOTIFY_REQ, msc_cc_tx_notify},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ),
	 MNCC_FACILITY_REQ, msc_cc_tx_facility},
	{ALL_STATES,
	 MNCC_START_DTMF_RSP, msc_cc_tx_start_dtmf_ack},
	{ALL_STATES,
	 MNCC_START_DTMF_REJ, msc_cc_tx_start_dtmf_rej},
	{ALL_STATES,
	 MNCC_STOP_DTMF_RSP, msc_cc_tx_stop_dtmf_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_HOLD_CNF, msc_cc_tx_hold_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_HOLD_REJ, msc_cc_tx_hold_rej},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_RETRIEVE_CNF, msc_cc_tx_retrieve_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_RETRIEVE_REJ, msc_cc_tx_retrieve_rej},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_MODIFY_REQ, msc_cc_tx_modify},
	{SBIT(GSM_CSTATE_MO_ORIG_MODIFY),
	 MNCC_MODIFY_RSP, msc_cc_tx_modify_complete},
	{SBIT(GSM_CSTATE_MO_ORIG_MODIFY),
	 MNCC_MODIFY_REJ, msc_cc_tx_modify_reject},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_USERINFO_REQ, msc_cc_tx_userinfo},
	/* clearing */
	{SBIT(GSM_CSTATE_INITIATED),
	 MNCC_REJ_REQ, msc_cc_tx_release_compl},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_DISCONNECT_IND) - SBIT(GSM_CSTATE_RELEASE_REQ) - SBIT(GSM_CSTATE_DISCONNECT_REQ), /* 5.4.4 */
	 MNCC_DISC_REQ, msc_cc_tx_disconnect},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ), /* 5.4.3.2 */
	 MNCC_REL_REQ, msc_cc_tx_release},
	/* special */
	{ALL_STATES,
	 MNCC_LCHAN_MODIFY, msc_cc_lchan_modify},
};

#define DOWNSLLEN \
	(sizeof(downstatelist) / sizeof(struct downstate))


int mncc_send(struct gsm_network *net, int msg_type, void *arg)
{
	int i, j, k, l, rc = 0;
	struct gsm_trans *trans = NULL, *transt;
	struct gsm_subscriber *subscr;
	struct gsm_lchan *lchan = NULL, *lchant;
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_mncc *data = arg, rel;

	/* handle special messages */
	switch(msg_type) {
	case MNCC_BRIDGE:
		return tch_bridge(net, arg);
	case MNCC_FRAME_DROP:
		return tch_recv(net, arg, 0);
	case MNCC_FRAME_RECV:
		return tch_recv(net, arg, 1);
	case GSM_TRAU_FRAME:
		return tch_frame(net, arg);
	}

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = data->callref;

	/* Find callref */
	trans = get_trans_ref(net, data->callref);

	/* Callref unknown */
	if (!trans) {
		if (msg_type != MNCC_SETUP_REQ) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"unknown callref %d\n", data->called.number,
				get_mncc_name(msg_type), data->callref);
			/* Invalid call reference */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_INVAL_TRANS_ID);
		}
		if (!data->called.number[0] && !data->imsi[0]) {
			DEBUGP(DCC, "(bts - trx - ts - ti) "
				"Received '%s' from MNCC with "
				"no number or IMSI\n", get_mncc_name(msg_type));
			/* Invalid number */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_INV_NR_FORMAT);
		}
		/* New transaction due to setup, find subscriber */
		if (data->called.number[0])
			subscr = subscr_get_by_extension(data->called.number);
		else
			subscr = subscr_get_by_imsi(data->imsi);
		/* If subscriber is not found */
		if (!subscr) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"unknown subscriber %s\n", data->called.number,
				get_mncc_name(msg_type), data->called.number);
			/* Unknown subscriber */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_UNASSIGNED_NR);
		}
		/* If subscriber is not "attached" */
		if (!subscr->lac) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"detached subscriber %s\n", data->called.number,
				get_mncc_name(msg_type), data->called.number);
			subscr_put(subscr);
			/* Temporarily out of order */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_DEST_OOO);
		}
		/* Create transaction */
		if (!(trans = talloc_zero(tall_trans_ctx, struct gsm_trans))) {
			DEBUGP(DCC, "No memory for trans.\n");
			subscr_put(subscr);
			/* Ressource unavailable */
			mncc_release_ind(net, NULL, data->callref,
					 GSM48_CAUSE_LOC_PRN_S_LU,
					 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			return -ENOMEM;
		}
		trans->callref = data->callref;
		trans->network = net;
		trans->transaction_id = 0xff; /* unassigned */
		llist_add_tail(&trans->entry, &net->trans_list);
		/* Assign subscriber to transaction */
		trans->subscr = subscr;
		/* Find lchan */
		for (i = 0; i < net->num_bts; i++) {
			bts = gsm_bts_num(net, i);
			for (j = 0; j < bts->num_trx; j++) {
				trx = gsm_bts_trx_num(bts, j);
				for (k = 0; k < TRX_NR_TS; k++) {
					ts = &trx->ts[k];
					for (l = 0; l < TS_MAX_LCHAN; l++) {
						lchant = &ts->lchan[l];
						if (lchant->subscr == subscr) {
							lchan = lchant;
							break;
						}
					}
				}
			}
		}

		/* If subscriber has no lchan */
		if (!lchan) {
			/* find transaction with this subscriber already paging */
			llist_for_each_entry(transt, &net->trans_list, entry) {
				/* Transaction of our lchan? */
				if (transt == trans ||
				    transt->subscr != subscr)
					continue;
				DEBUGP(DCC, "(bts %d trx - ts - ti -- sub %s) "
					"Received '%s' from MNCC with "
					"unallocated channel, paging already "
					"started.\n", bts->nr,
					data->called.number,
					get_mncc_name(msg_type));
				return 0;
			}
			/* store setup informations until paging was successfull */
			memcpy(&trans->cc_msg, data, sizeof(struct gsm_mncc));
			/* start paging subscriber on all BTS with her location */
			subscr->net = net;
			bts = NULL;
			do {
				bts = gsm_bts_by_lac(net, subscr->lac, bts);
				if (!bts)
					break;
				DEBUGP(DCC, "(bts %d trx - ts - ti -- sub %s) "
					"Received '%s' from MNCC with "
					"unallocated channel, paging.\n",
					bts->nr, data->called.number,
					get_mncc_name(msg_type));
				/* Trigger paging */
				paging_request(net, subscr, RSL_CHANNEED_TCH_F,
						setup_trig_pag_evt, subscr);
			} while (1);
			return 0;
		}
		/* Assign lchan */
		trans->lchan = lchan;
		use_lchan(lchan);
	}
	lchan = trans->lchan;

	/* if paging did not respond yet */
	if (!lchan) {
		DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
			"Received '%s' from MNCC in paging state\n",
			(trans->subscr)?(trans->subscr->extension):"-",
			get_mncc_name(msg_type));
		mncc_set_cause(&rel, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_NORM_CALL_CLEAR);
		if (msg_type == MNCC_REL_REQ)
			rc = mncc_recvmsg(net, trans, MNCC_REL_CNF, &rel);
		else
			rc = mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
		trans->callref = 0;
		free_trans(trans);
		return rc;
	}

	DEBUGP(DCC, "(bts %d trx %d ts %d ti %02x sub %s) "
		"Received '%s' from MNCC in state %d (%s)\n",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		trans->transaction_id,
		(lchan->subscr)?(lchan->subscr->extension):"-",
		get_mncc_name(msg_type), trans->state,
		cc_state_names[trans->state]);

	/* Find function for current state and message */
	for (i = 0; i < DOWNSLLEN; i++)
		if ((msg_type == downstatelist[i].type)
		 && ((1 << trans->state) & downstatelist[i].states))
			break;
	if (i == DOWNSLLEN) {
		DEBUGP(DCC, "Message unhandled at this state.\n");
		return 0;
	}

	rc = downstatelist[i].rout(trans, arg);

	return rc;
}


static struct datastate {
	u_int32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, struct msgb *msg);
} datastatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_NULL), /* 5.2.1.2 */
	 GSM48_MT_CC_SETUP, msc_cc_rx_setup},
	{SBIT(GSM_CSTATE_NULL), /* 5.2.1.2 */
	 GSM48_MT_CC_EMERG_SETUP, msc_cc_rx_setup},
	{SBIT(GSM_CSTATE_CONNECT_IND), /* 5.2.1.2 */
	 GSM48_MT_CC_CONNECT_ACK, msc_cc_rx_connect_ack},
	/* mobile terminating call establishment */
	{SBIT(GSM_CSTATE_CALL_PRESENT), /* 5.2.2.3.2 */
	 GSM48_MT_CC_CALL_CONF, msc_cc_rx_call_conf},
	{SBIT(GSM_CSTATE_CALL_PRESENT) | SBIT(GSM_CSTATE_MO_TERM_CALL_CONF), /* ???? | 5.2.2.3.2 */
	 GSM48_MT_CC_ALERTING, msc_cc_rx_alerting},
	{SBIT(GSM_CSTATE_CALL_PRESENT) | SBIT(GSM_CSTATE_MO_TERM_CALL_CONF) | SBIT(GSM_CSTATE_CALL_RECEIVED), /* (5.2.2.6) | 5.2.2.6 | 5.2.2.6 */
	 GSM48_MT_CC_CONNECT, msc_cc_rx_connect},
	 /* signalling during call */
	{ALL_STATES - SBIT(GSM_CSTATE_NULL),
	 GSM48_MT_CC_FACILITY, msc_cc_rx_facility},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_NOTIFY, msc_cc_rx_notify},
	{ALL_STATES,
	 GSM48_MT_CC_START_DTMF, msc_cc_rx_start_dtmf},
	{ALL_STATES,
	 GSM48_MT_CC_STOP_DTMF, msc_cc_rx_stop_dtmf},
	{ALL_STATES,
	 GSM48_MT_CC_STATUS_ENQ, msc_cc_rx_status_enq},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_HOLD, msc_cc_rx_hold},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_RETR, msc_cc_rx_retrieve},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_MODIFY, msc_cc_rx_modify},
	{SBIT(GSM_CSTATE_MO_TERM_MODIFY),
	 GSM48_MT_CC_MODIFY_COMPL, msc_cc_rx_modify_complete},
	{SBIT(GSM_CSTATE_MO_TERM_MODIFY),
	 GSM48_MT_CC_MODIFY_REJECT, msc_cc_rx_modify_reject},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_USER_INFO, msc_cc_rx_userinfo},
	/* clearing */
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ), /* 5.4.3.2 */
	 GSM48_MT_CC_DISCONNECT, msc_cc_rx_disconnect},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL), /* 5.4.4.1.2.2 */
	 GSM48_MT_CC_RELEASE, msc_cc_rx_release},
	{ALL_STATES, /* 5.4.3.4 */
	 GSM48_MT_CC_RELEASE_COMPL, msc_cc_rx_release_compl},
};

#define DATASLLEN \
	(sizeof(datastatelist) / sizeof(struct datastate))

int msc_rcv_cc(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type & 0xbf;
	u_int8_t transaction_id = (gh->proto_discr & 0xf0) ^ 0x80; /* flip */
	struct gsm_lchan *lchan = msg->lchan;
	struct gsm_trans *trans = NULL, *transt;
	struct gsm_network *net = lchan->ts->trx->bts->network;
	int i, rc = 0;

	if (msg_type & 0x80) {
		DEBUGP(DCC, "MSG 0x%2x not defined for PD error\n", msg_type);
		return -EINVAL;
	}

	/* Find transaction */
	llist_for_each_entry(transt, &net->trans_list, entry) {
		/* Transaction of our lchan? */
		if (transt->lchan == lchan
			&& transt->transaction_id == transaction_id) {
			trans = transt;
		}
	}

	DEBUGP(DCC, "(bts %d trx %d ts %d ti %02x sub %s) "
		"Received '%s' from MS in state %d (%s)\n",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		transaction_id, (lchan->subscr)?(lchan->subscr->extension):"-",
		gsm48_cc_msg_name(msg_type), trans?(trans->state):0,
		cc_state_names[trans?(trans->state):0]);

	/* Create transaction */
	if (!trans) {
		DEBUGP(DCC, "Unknown transaction ID %02x, "
			"creating new trans.\n", transaction_id);
		/* Create transaction */
		if (!(trans = talloc_zero(tall_trans_ctx, struct gsm_trans))) {
			DEBUGP(DCC, "No memory for trans.\n");
			rc = gsm48_tx_simple(msg->lchan,
					     GSM48_PDISC_CC | transaction_id,
					     GSM48_MT_CC_RELEASE_COMPL);
			return -ENOMEM;
		}
		llist_add_tail(&trans->entry, &net->trans_list);
		/* Assign transaction */
		trans->callref = new_callref++;
		trans->network = net;
		trans->transaction_id = transaction_id;
		trans->lchan = lchan;
		use_lchan(lchan);
		if (lchan->subscr) {
			trans->subscr = lchan->subscr;
			subscr_get(trans->subscr);
		}
	}

	/* find function for current state and message */
	for (i = 0; i < DATASLLEN; i++)
		if ((msg_type == datastatelist[i].type)
		 && ((1 << trans->state) & datastatelist[i].states))
			break;
	if (i == DATASLLEN) {
		DEBUGP(DCC, "Message unhandled at this state.\n");
		return 0;
	}

	rc = datastatelist[i].rout(trans, msg);

	return rc;
}
