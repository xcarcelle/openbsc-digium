/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
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
#include <sys/types.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/mncc.h>
#include <openbsc/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/transaction.h>
#include <openbsc/rtp_proxy.h>

void *tall_call_ctx;

static struct mncc_names {
	char *name;
	int value;
} mncc_names[] = {
	{"MNCC_SETUP_REQ",	0x0101},
	{"MNCC_SETUP_IND",	0x0102},
	{"MNCC_SETUP_RSP",	0x0103},
	{"MNCC_SETUP_CNF",	0x0104},
	{"MNCC_SETUP_COMPL_REQ",0x0105},
	{"MNCC_SETUP_COMPL_IND",0x0106},
	{"MNCC_CALL_CONF_IND",	0x0107},
	{"MNCC_CALL_PROC_REQ",	0x0108},
	{"MNCC_PROGRESS_REQ",	0x0109},
	{"MNCC_ALERT_REQ",	0x010a},
	{"MNCC_ALERT_IND",	0x010b},
	{"MNCC_NOTIFY_REQ",	0x010c},
	{"MNCC_NOTIFY_IND",	0x010d},
	{"MNCC_DISC_REQ",	0x010e},
	{"MNCC_DISC_IND",	0x010f},
	{"MNCC_REL_REQ",	0x0110},
	{"MNCC_REL_IND",	0x0111},
	{"MNCC_REL_CNF",	0x0112},
	{"MNCC_FACILITY_REQ",	0x0113},
	{"MNCC_FACILITY_IND",	0x0114},
	{"MNCC_START_DTMF_IND",	0x0115},
	{"MNCC_START_DTMF_RSP",	0x0116},
	{"MNCC_START_DTMF_REJ",	0x0117},
	{"MNCC_STOP_DTMF_IND",	0x0118},
	{"MNCC_STOP_DTMF_RSP",	0x0119},
	{"MNCC_MODIFY_REQ",	0x011a},
	{"MNCC_MODIFY_IND",	0x011b},
	{"MNCC_MODIFY_RSP",	0x011c},
	{"MNCC_MODIFY_CNF",	0x011d},
	{"MNCC_MODIFY_REJ",	0x011e},
	{"MNCC_HOLD_IND",	0x011f},
	{"MNCC_HOLD_CNF",	0x0120},
	{"MNCC_HOLD_REJ",	0x0121},
	{"MNCC_RETRIEVE_IND",	0x0122},
	{"MNCC_RETRIEVE_CNF",	0x0123},
	{"MNCC_RETRIEVE_REJ",	0x0124},
	{"MNCC_USERINFO_REQ",	0x0125},
	{"MNCC_USERINFO_IND",	0x0126},
	{"MNCC_REJ_REQ",	0x0127},
	{"MNCC_REJ_IND",	0x0128},

	{"MNCC_BRIDGE",		0x0200},
	{"MNCC_FRAME_RECV",	0x0201},
	{"MNCC_FRAME_DROP",	0x0202},
	{"MNCC_LCHAN_MODIFY",	0x0203},

	{"GSM_TCH_FRAME",	0x0300},

	{NULL, 0} };

static LLIST_HEAD(call_list);

static u_int32_t new_callref = 0x00000001;

char *get_mncc_name(int value)
{
	int i;

	for (i = 0; mncc_names[i].name; i++) {
		if (mncc_names[i].value == value)
			return mncc_names[i].name;
	}

	return "MNCC_Unknown";
}

static void free_call(struct gsm_call *call)
{
	llist_del(&call->entry);
	DEBUGP(DMNCC, "(call %x) Call removed.\n", call->callref);
	talloc_free(call);
}


struct gsm_call *get_call_ref(u_int32_t callref)
{
	struct gsm_call *callt;

	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref)
			return callt;
	}
	return NULL;
}

void mncc_set_cause(struct gsm_mncc *data, int loc, int val)
{
	data->fields |= MNCC_F_CAUSE;
	data->cause.location = loc;
	data->cause.value = val;
}

/* on incoming call, look up database and send setup to remote subscr. */
static int mncc_setup_ind(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *setup)
{
	struct gsm_mncc mncc;
	struct gsm_call *remote;

	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;

	/* already have remote call */
	if (call->remote_ref)
		return 0;
	
	/* transfer mode 1 would be packet mode, which was never specified */
	if (setup->bearer_cap.mode != 0) {
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) We don't support "
			"packet mode\n", call->callref);
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_BEARER_CA_UNAVAIL);
		goto out_reject;
	}

	/* we currently only do speech */
	if (setup->bearer_cap.transfer != GSM_MNCC_BCAP_SPEECH) {
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) We only support "
			"voice calls\n", call->callref);
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_BEARER_CA_UNAVAIL);
		goto out_reject;
	}

	/* create remote call */
	if (!(remote = talloc(tall_call_ctx, struct gsm_call))) {
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		goto out_reject;
	}
	llist_add_tail(&remote->entry, &call_list);
	remote->net = call->net;
	remote->callref = new_callref++;
	DEBUGP(DMNCC, "(call %x) Creating new remote instance %x.\n",
		call->callref, remote->callref);

	/* link remote call */
	call->remote_ref = remote->callref;
	remote->remote_ref = call->callref;

	/* modify mode */
	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;
	mncc.lchan_mode = GSM48_CMODE_SPEECH_EFR;
	DEBUGP(DMNCC, "(call %x) Modify channel mode.\n", call->callref);
	mncc_send(call->net, MNCC_LCHAN_MODIFY, &mncc);

	/* send call proceeding */
	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Accepting call.\n", call->callref);
	mncc_send(call->net, MNCC_CALL_PROC_REQ, &mncc);

	/* send setup to remote */
//	setup->fields |= MNCC_F_SIGNAL;
//	setup->signal = GSM48_SIGNAL_DIALTONE;
	setup->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding SETUP to remote.\n", call->callref);
	return mncc_send(remote->net, MNCC_SETUP_REQ, setup);

out_reject:
	mncc_send(call->net, MNCC_REJ_REQ, &mncc);
	free_call(call);
	return 0;
}

static int mncc_alert_ind(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *alert)
{
	struct gsm_call *remote;

	/* send alerting to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	alert->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding ALERT to remote.\n", call->callref);
	return mncc_send(remote->net, MNCC_ALERT_REQ, alert);
}

static int mncc_notify_ind(struct gsm_call *call, int msg_type,
			   struct gsm_mncc *notify)
{
	struct gsm_call *remote;

	/* send notify to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	notify->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding NOTIF to remote.\n", call->callref);
	return mncc_send(remote->net, MNCC_NOTIFY_REQ, notify);
}

static int mncc_setup_cnf(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *connect)
{
	struct gsm_mncc connect_ack, frame_recv;
	struct gsm_network *net = call->net;
	struct gsm_call *remote;
	u_int32_t refs[2];

	/* acknowledge connect */
	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Acknowledge SETUP.\n", call->callref);
	mncc_send(call->net, MNCC_SETUP_COMPL_REQ, &connect_ack);

	/* send connect message to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	connect->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Sending CONNECT to remote.\n", call->callref);
	mncc_send(remote->net, MNCC_SETUP_RSP, connect);

	/* bridge tch */
	refs[0] = call->callref;
	refs[1] = call->remote_ref;
	DEBUGP(DMNCC, "(call %x) Bridging with remote.\n", call->callref);

	/* in direct mode, we always have to bridge the channels */
	if (ipacc_rtp_direct)
		return mncc_send(call->net, MNCC_BRIDGE, refs);

	/* proxy mode */
	if (!net->handover.active) {
		/* in the no-handover case, we can bridge, i.e. use
		 * the old RTP proxy code */
		return mncc_send(call->net, MNCC_BRIDGE, refs);
	} else {
		/* in case of handover, we need to re-write the RTP
		 * SSRC, sequence and timestamp values and thus
		 * need to enable RTP receive for both directions */
		memset(&frame_recv, 0, sizeof(struct gsm_mncc));
		frame_recv.callref = call->callref;
		mncc_send(call->net, MNCC_FRAME_RECV, &frame_recv);
		frame_recv.callref = call->remote_ref;
		return mncc_send(call->net, MNCC_FRAME_RECV, &frame_recv);
	}
}

static int mncc_disc_ind(struct gsm_call *call, int msg_type,
			 struct gsm_mncc *disc)
{
	struct gsm_call *remote;

	/* send release */
	DEBUGP(DMNCC, "(call %x) Releasing call with cause %d\n",
		call->callref, disc->cause.value);
	mncc_send(call->net, MNCC_REL_REQ, disc);

	/* send disc to remote */
	if (!(remote = get_call_ref(call->remote_ref))) {
		return 0;
	}
	disc->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Disconnecting remote with cause %d\n",
		remote->callref, disc->cause.value);
	return mncc_send(remote->net, MNCC_DISC_REQ, disc);
}

static int mncc_rel_ind(struct gsm_call *call, int msg_type, struct gsm_mncc *rel)
{
	struct gsm_call *remote;

	/* send release to remote */
	if (!(remote = get_call_ref(call->remote_ref))) {
		free_call(call);
		return 0;
	}
	rel->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Releasing remote with cause %d\n",
		call->callref, rel->cause.value);
	mncc_send(remote->net, MNCC_REL_REQ, rel);

	free_call(call);

	return 0;
}

static int mncc_rel_cnf(struct gsm_call *call, int msg_type, struct gsm_mncc *rel)
{
	free_call(call);
	return 0;
}

/* receiving a TCH/F frame from the BSC code */
static int mncc_rcv_tchf(struct gsm_call *call, int msg_type,
			 struct gsm_data_frame *dfr)
{
	struct gsm_trans *remote_trans;

	remote_trans = trans_find_by_callref(call->net, call->remote_ref);

	/* this shouldn't really happen */
	if (!remote_trans || !remote_trans->lchan) {
		LOGP(DMNCC, LOGL_ERROR, "No transaction or transaction without lchan?!?\n");
		return -EIO;
	}

	/* RTP socket of remote end has meanwhile died */
	if (!remote_trans->lchan->abis_ip.rtp_socket)
		return -EIO;

	return rtp_send_frame(remote_trans->lchan->abis_ip.rtp_socket, dfr);
}


int mncc_recv(struct gsm_network *net, int msg_type, void *arg)
{
	struct gsm_mncc *data = arg;
	int callref;
	struct gsm_call *call = NULL, *callt;
	int rc = 0;

	/* Special messages */
	switch(msg_type) {
	}
	
	/* find callref */
	callref = data->callref;
	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref) {
			call = callt;
			break;
		}
	}

	/* create callref, if setup is received */
	if (!call) {
		if (msg_type != MNCC_SETUP_IND)
			return 0; /* drop */
		/* create call */
		if (!(call = talloc_zero(tall_call_ctx, struct gsm_call))) {
			struct gsm_mncc rel;
			
			memset(&rel, 0, sizeof(struct gsm_mncc));
			rel.callref = callref;
			mncc_set_cause(&rel, GSM48_CAUSE_LOC_PRN_S_LU,
				       GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			mncc_send(net, MNCC_REL_REQ, &rel);
			return 0;
		}
		llist_add_tail(&call->entry, &call_list);
		call->net = net;
		call->callref = callref;
		DEBUGP(DMNCC, "(call %x) Call created.\n", call->callref);
	}

	switch (msg_type) {
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
		break;
	default:
		DEBUGP(DMNCC, "(call %x) Received message %s\n", call->callref,
			get_mncc_name(msg_type));
		break;
	}

	switch(msg_type) {
	case MNCC_SETUP_IND:
		rc = mncc_setup_ind(call, msg_type, arg);
		break;
	case MNCC_SETUP_CNF:
		rc = mncc_setup_cnf(call, msg_type, arg);
		break;
	case MNCC_SETUP_COMPL_IND:
		break;
	case MNCC_CALL_CONF_IND:
		/* we now need to MODIFY the channel */
		data->lchan_mode = GSM48_CMODE_SPEECH_EFR;
		mncc_send(call->net, MNCC_LCHAN_MODIFY, data);
		break;
	case MNCC_ALERT_IND:
		rc = mncc_alert_ind(call, msg_type, arg);
		break;
	case MNCC_NOTIFY_IND:
		rc = mncc_notify_ind(call, msg_type, arg);
		break;
	case MNCC_DISC_IND:
		rc = mncc_disc_ind(call, msg_type, arg);
		break;
	case MNCC_REL_IND:
	case MNCC_REJ_IND:
		rc = mncc_rel_ind(call, msg_type, arg);
		break;
	case MNCC_REL_CNF:
		rc = mncc_rel_cnf(call, msg_type, arg);
		break;
	case MNCC_FACILITY_IND:
		break;
	case MNCC_START_DTMF_IND:
		break;
	case MNCC_STOP_DTMF_IND:
		break;
	case MNCC_MODIFY_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting MODIFY with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_send(net, MNCC_MODIFY_REJ, data);
		break;
	case MNCC_MODIFY_CNF:
		break;
	case MNCC_HOLD_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting HOLD with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_send(net, MNCC_HOLD_REJ, data);
		break;
	case MNCC_RETRIEVE_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting RETRIEVE with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_send(net, MNCC_RETRIEVE_REJ, data);
		break;
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
		rc = mncc_rcv_tchf(call, msg_type, arg);
		break;
	default:
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) Message unhandled\n", callref);
		break;
	}

	return rc;
}
