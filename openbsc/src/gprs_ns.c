/* GPRS Networks Service (NS) messages on the Gb interface
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05) */

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

/* Some introduction into NS:  NS is used typically on top of frame relay,
 * but in the ip.access world it is encapsulated in UDP packets.  It serves
 * as an intermediate shim betwen BSSGP and the underlying medium.  It doesn't
 * do much, apart from providing congestion notification and status indication.
 *
 * Terms:
 * 	NS		Network Service
 *	NSVC		NS Virtual Connection
 *	NSEI		NS Entity Identifier
 *	NSVL		NS Virtual Link
 *	NSVLI		NS Virtual Link Identifier
 *	BVC		BSSGP Virtual Connection
 *	BVCI		BSSGP Virtual Connection Identifier
 *	NSVCG		NS Virtual Connection Goup
 *	Blocked		NS-VC cannot be used for user traffic
 *	Alive		Ability of a NS-VC to provide communication
 *
 *  There can be multiple BSSGP virtual connections over one (group of) NSVC's.  BSSGP will
 * therefore identify the BSSGP virtual connection by a BVCI passed down to NS.
 * NS then has to firgure out which NSVC's are responsible for this BVCI.
 * Those mappings are administratively configured.
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <osmocore/talloc.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>

#define NS_ALLOC_SIZE	1024

static const struct tlv_definition ns_att_tlvdef = {
	.def = {
		[NS_IE_CAUSE]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_VCI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_PDU]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_BVCI]	= { TLV_TYPE_TvLV, 0 },
		[NS_IE_NSEI]	= { TLV_TYPE_TvLV, 0 },
	},
};

#define NSE_S_BLOCKED	0x0001
#define NSE_S_ALIVE	0x0002

struct gprs_nsvc {
	struct llist_head list;

	u_int16_t nsei;		/* end-to-end significance */
	u_int16_t nsvci;	/* uniquely identifies NS-VC at SGSN */

	u_int32_t state;

	struct timer_list alive_timer;
	int timer_is_tns_alive;
	int alive_retries;
};

/* FIXME: dynamically search for the matching NSVC */
static struct gprs_nsvc dummy_nsvc = { .state = NSE_S_BLOCKED | NSE_S_ALIVE };

/* Section 10.3.2, Table 13 */
static const char *ns_cause_str[] = {
	[NS_CAUSE_TRANSIT_FAIL]		= "Transit network failure",
	[NS_CAUSE_OM_INTERVENTION] 	= "O&M intervention",
	[NS_CAUSE_EQUIP_FAIL]		= "Equipment failure",
	[NS_CAUSE_NSVC_BLOCKED]		= "NS-VC blocked",
	[NS_CAUSE_NSVC_UNKNOWN]		= "NS-VC unknown",
	[NS_CAUSE_BVCI_UNKNOWN]		= "BVCI unknown",
	[NS_CAUSE_SEM_INCORR_PDU]	= "Semantically incorrect PDU",
	[NS_CAUSE_PDU_INCOMP_PSTATE]	= "PDU not compatible with protocol state",
	[NS_CAUSE_PROTO_ERR_UNSPEC]	= "Protocol error, unspecified",
	[NS_CAUSE_INVAL_ESSENT_IE]	= "Invalid essential IE",
	[NS_CAUSE_MISSING_ESSENT_IE]	= "Missing essential IE",
};

static const char *gprs_ns_cause_str(enum ns_cause cause)
{
	if (cause >= ARRAY_SIZE(ns_cause_str))
		return "undefined";

	if (ns_cause_str[cause])
		return ns_cause_str[cause];

	return "undefined";
}

static int gprs_ns_tx(struct msgb *msg)
{
	return ipac_gprs_send(msg);
}

static int gprs_ns_tx_simple(struct gprs_ns_link *link, u_int8_t pdu_type)
{
	struct msgb *msg = msgb_alloc(NS_ALLOC_SIZE, "GPRS/NS");
	struct gprs_ns_hdr *nsh;

	if (!msg)
		return -ENOMEM;

	nsh = (struct gprs_ns_hdr *) msgb_put(msg, sizeof(*nsh));

	nsh->pdu_type = pdu_type;

	return gprs_ns_tx(msg);
}

#define NS_TIMER_ALIVE	3, 0 	/* after 3 seconds without response, we retry */
#define NS_TIMER_TEST	30, 0	/* every 10 seconds we check if the BTS is still alive */
#define NS_ALIVE_RETRIES  10	/* after 3 failed retransmit we declare BTS as dead */

static void gprs_ns_alive_cb(void *data)
{
	struct gprs_nsvc *nsvc = data;

	if (nsvc->timer_is_tns_alive) {
		/* Tns-alive case: we expired without response ! */
		nsvc->alive_retries++;
		if (nsvc->alive_retries > NS_ALIVE_RETRIES) {
			/* mark as dead and blocked */
			nsvc->state = NSE_S_BLOCKED;
			DEBUGP(DGPRS, "Tns-alive more then %u retries, "
				" blocking NS-VC\n", NS_ALIVE_RETRIES);
			/* FIXME: inform higher layers */
			return;
		}
	} else {
		/* Tns-test case: send NS-ALIVE PDU */
		gprs_ns_tx_simple(NULL, NS_PDUT_ALIVE);
		/* start Tns-alive timer */
		nsvc->timer_is_tns_alive = 1;
	}
	bsc_schedule_timer(&nsvc->alive_timer, NS_TIMER_ALIVE);
}

/* Section 9.2.6 */
static int gprs_ns_tx_reset_ack(u_int16_t nsvci, u_int16_t nsei)
{
	struct msgb *msg = msgb_alloc(NS_ALLOC_SIZE, "GPRS/NS");
	struct gprs_ns_hdr *nsh;

	if (!msg)
		return -ENOMEM;

	nsvci = htons(nsvci);
	nsei = htons(nsei);

	nsh = (struct gprs_ns_hdr *) msgb_put(msg, sizeof(*nsh));

	nsh->pdu_type = NS_PDUT_RESET_ACK;

	msgb_tvlv_put(msg, NS_IE_VCI, 2, (u_int8_t *)&nsvci);
	msgb_tvlv_put(msg, NS_IE_NSEI, 2, (u_int8_t *)&nsei);

	return gprs_ns_tx(msg);
}

/* Section 9.2.10: transmit side */
int gprs_ns_sendmsg(struct gprs_ns_link *link, u_int16_t bvci,
		    struct msgb *msg)
{
	struct gprs_ns_hdr *nsh;

	nsh = (struct gprs_ns_hdr *) msgb_push(msg, sizeof(*nsh) + 3);
	if (!nsh) {
		DEBUGP(DGPRS, "Not enough headroom for NS header\n");
		return -EIO;
	}

	nsh->pdu_type = NS_PDUT_UNITDATA;
	/* spare octet in data[0] */
	nsh->data[1] = bvci >> 8;
	nsh->data[2] = bvci & 0xff;

	return gprs_ns_tx(msg);
}

/* Section 9.2.10: receive side */
static int gprs_ns_rx_unitdata(struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *)msg->l2h;
	u_int16_t bvci;

	/* spare octet in data[0] */
	bvci = nsh->data[1] << 8 | nsh->data[2];
	msg->l3h = &nsh->data[3];

	/* call upper layer (BSSGP) */
	return gprs_bssgp_rcvmsg(msg, bvci);
}

/* Section 9.2.7 */
static int gprs_ns_rx_status(struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = msg->l2h;
	struct tlv_parsed tp;
	u_int8_t cause;
	int rc;

	DEBUGP(DGPRS, "NS STATUS ");

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data, msgb_l2len(msg), 0, 0);

	if (!TLVP_PRESENT(&tp, NS_IE_CAUSE)) {
		DEBUGPC(DGPRS, "missing cause IE\n");
		return -EINVAL;
	}

	cause = *TLVP_VAL(&tp, NS_IE_CAUSE);
	DEBUGPC(DGPRS, "cause=%s\n", gprs_ns_cause_str(cause));

	return 0;
}

/* Section 7.3 */
static int gprs_ns_rx_reset(struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct gprs_nsvc *nsvc = &dummy_nsvc;
	struct tlv_parsed tp;
	u_int8_t *cause;
	u_int16_t *nsvci, *nsei;
	int rc;

	DEBUGP(DGPRS, "NS RESET ");

	rc = tlv_parse(&tp, &ns_att_tlvdef, nsh->data, msgb_l2len(msg), 0, 0);

	if (!TLVP_PRESENT(&tp, NS_IE_CAUSE) ||
	    !TLVP_PRESENT(&tp, NS_IE_VCI) ||
	    !TLVP_PRESENT(&tp, NS_IE_NSEI)) {
		/* FIXME: respond with NS_CAUSE_MISSING_ESSENT_IE */
		DEBUGPC(DGPRS, "Missing mandatory IE\n");
		return -EINVAL;
	}

	cause = (u_int8_t *) TLVP_VAL(&tp, NS_IE_CAUSE);
	nsvci = (u_int16_t *) TLVP_VAL(&tp, NS_IE_VCI);
	nsei = (u_int16_t *) TLVP_VAL(&tp, NS_IE_NSEI);

	*nsvci = ntohs(*nsvci);
	*nsei = ntohs(*nsei);

	DEBUGPC(DGPRS, "cause=%s, NSVCI=%u, NSEI=%u\n",
		gprs_ns_cause_str(*cause), *nsvci, *nsei);

	/* mark the NS-VC as blocked and alive */
	nsvc->state = NSE_S_BLOCKED | NSE_S_ALIVE;
	nsvc->nsei = *nsei;
	nsvc->nsvci = *nsvci;

	/* start the test procedure */
	nsvc->alive_timer.cb = gprs_ns_alive_cb;
	nsvc->alive_timer.data = nsvc;
	bsc_schedule_timer(&nsvc->alive_timer, NS_TIMER_ALIVE);

	return gprs_ns_tx_reset_ack(*nsvci, *nsei);
}

/* main entry point, here incoming NS frames enter */
int gprs_ns_rcvmsg(struct msgb *msg)
{
	struct gprs_ns_hdr *nsh = (struct gprs_ns_hdr *) msg->l2h;
	struct gprs_nsvc *nsvc = &dummy_nsvc;
	int rc = 0;

	switch (nsh->pdu_type) {
	case NS_PDUT_ALIVE:
		/* remote end inquires whether we're still alive,
		 * we need to respond with ALIVE_ACK */
		rc = gprs_ns_tx_simple(NULL, NS_PDUT_ALIVE_ACK);
		break;
	case NS_PDUT_ALIVE_ACK:
		/* stop Tns-alive */
		bsc_del_timer(&nsvc->alive_timer);
		/* start Tns-test */
		nsvc->timer_is_tns_alive = 0;
		bsc_schedule_timer(&nsvc->alive_timer, NS_TIMER_TEST);
		break;
	case NS_PDUT_UNITDATA:
		/* actual user data */
		rc = gprs_ns_rx_unitdata(msg);
		break;
	case NS_PDUT_STATUS:
		rc = gprs_ns_rx_status(msg);
		break;
	case NS_PDUT_RESET:
		rc = gprs_ns_rx_reset(msg);
		break;
	case NS_PDUT_RESET_ACK:
		/* FIXME: mark remote NS-VC as blocked + active */
		break;
	case NS_PDUT_UNBLOCK:
		/* Section 7.2: unblocking procedure */
		DEBUGP(DGPRS, "NS UNBLOCK\n");
		nsvc->state &= ~NSE_S_BLOCKED;
		rc = gprs_ns_tx_simple(NULL, NS_PDUT_UNBLOCK_ACK);
		break;
	case NS_PDUT_UNBLOCK_ACK:
		/* FIXME: mark remote NS-VC as unblocked + active */
		break;
	case NS_PDUT_BLOCK:
		DEBUGP(DGPRS, "NS BLOCK\n");
		nsvc->state |= NSE_S_BLOCKED;
		rc = gprs_ns_tx_simple(NULL, NS_PDUT_UNBLOCK_ACK);
		break;
	case NS_PDUT_BLOCK_ACK:
		/* FIXME: mark remote NS-VC as blocked + active */
		break;
	default:
		DEBUGP(DGPRS, "Unknown NS PDU type 0x%02x\n", nsh->pdu_type);
		rc = -EINVAL;
		break;
	}
	return rc;
}

