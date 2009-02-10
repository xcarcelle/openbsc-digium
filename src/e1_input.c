/* OpenBSC Abis interface to E1 */

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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <mISDNif.h>

//#define AF_COMPATIBILITY_FUNC
//#include <compat_af_isdn.h>
#define AF_ISDN 34
#define PF_ISDN AF_ISDN

#include <openbsc/select.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/linuxlist.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/trau_mux.h>

#define NUM_E1_TS	32

/* list of all E1 drivers */
static LLIST_HEAD(driver_list);

/* list of all E1 lines */
static LLIST_HEAD(line_list);

#if 0
/*
 * pcap writing of the misdn load
 * pcap format is from http://wiki.wireshark.org/Development/LibpcapFileFormat
 */
#define DLT_LINUX_LAPD		177
#define PCAP_INPUT		0
#define PCAP_OUTPUT		1

struct pcap_hdr {
	u_int32_t magic_number;
	u_int16_t version_major;
	u_int16_t version_minor;
	int32_t  thiszone;
	u_int32_t sigfigs;
	u_int32_t snaplen;
	u_int32_t network;
} __attribute__((packed));

struct pcaprec_hdr {
	u_int32_t ts_sec;
	u_int32_t ts_usec;
	u_int32_t incl_len;
	u_int32_t orig_len;
} __attribute__((packed));

struct fake_linux_lapd_header {
        u_int16_t pkttype;
	u_int16_t hatype;
	u_int16_t halen;
	u_int64_t addr;
	int16_t protocol;
} __attribute__((packed));

struct lapd_header {
	u_int8_t ea1 : 1;
	u_int8_t cr : 1;
	u_int8_t sapi : 6;
	u_int8_t ea2 : 1;
	u_int8_t tei : 7;
	u_int8_t control_foo; /* fake UM's ... */
} __attribute__((packed));

static_assert((int)&((struct fake_linux_lapd_header*)NULL)->hatype == 2,	hatype_offset);
static_assert((int)&((struct fake_linux_lapd_header*)NULL)->halen == 4,		halen_offset);
static_assert((int)&((struct fake_linux_lapd_header*)NULL)->addr == 6,		addr_offset);
static_assert((int)&((struct fake_linux_lapd_header*)NULL)->protocol == 14,	proto_offset);
static_assert(sizeof(struct fake_linux_lapd_header) == 16,			lapd_header_size);


static int pcap_fd = -1;

void mi_set_pcap_fd(int fd)
{
	int ret;
	struct pcap_hdr header = {
		.magic_number	= 0xa1b2c3d4,
		.version_major	= 2,
		.version_minor	= 4,
		.thiszone	= 0,
		.sigfigs	= 0,
		.snaplen	= 65535,
		.network	= DLT_LINUX_LAPD,
	};

	pcap_fd = fd;
	ret = write(pcap_fd, &header, sizeof(header));
}

/* This currently only works for the D-Channel */
static void write_pcap_packet(int direction, struct sockaddr_mISDN* addr,
			      struct msgb *msg) {
	if (pcap_fd < 0)
		return;

	int ret;
	time_t cur_time;
	struct tm *tm;

	struct fake_linux_lapd_header header = {
		.pkttype	= 4,
		.hatype		= 0,
		.halen		= 0,
		.addr		= direction == PCAP_OUTPUT ? 0x0 : 0x1,
		.protocol	= ntohs(48),
	};

	struct lapd_header lapd_header = {
		.ea1		= 0,
		.cr		= direction == PCAP_OUTPUT ? 1 : 0,
		.sapi		= addr->sapi & 0x3F,
		.ea2		= 1,
		.tei		= addr->tei & 0x7F,
		.control_foo	= 0x03 /* UI */,
	};	

	struct pcaprec_hdr payload_header = {
		.ts_sec	    = 0,
		.ts_usec    = 0,
		.incl_len   = msg->len + sizeof(struct fake_linux_lapd_header)
				+ sizeof(struct lapd_header)
				- MISDN_HEADER_LEN,
		.orig_len   = msg->len + sizeof(struct fake_linux_lapd_header)
				+ sizeof(struct lapd_header)
				- MISDN_HEADER_LEN,
	};


	cur_time = time(NULL);
	tm = localtime(&cur_time);
	payload_header.ts_sec = mktime(tm);

	ret = write(pcap_fd, &payload_header, sizeof(payload_header));
	ret = write(pcap_fd, &header, sizeof(header));
	ret = write(pcap_fd, &lapd_header, sizeof(lapd_header));
	ret = write(pcap_fd, msg->data + MISDN_HEADER_LEN,
			msg->len - MISDN_HEADER_LEN);
}
#endif

/* callback when a TRAU frame was received */
static int subch_cb(struct subch_demux *dmx, int ch, u_int8_t *data, int len,
		    void *_priv)
{
	struct e1inp_ts *e1i_ts = _priv;
	struct gsm_e1_subslot src_ss;

	src_ss.e1_nr = e1i_ts->line->num;
	src_ss.e1_ts = e1i_ts->num;
	src_ss.e1_ts_ss = ch;

	return trau_mux_input(&src_ss, data, len);
}

int abis_rsl_sendmsg(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link;
	struct e1inp_driver *e1inp_driver;

	msg->l2h = msg->data;

	if (!msg->trx || !msg->trx->rsl_link) {
		fprintf(stderr, "rsl_sendmsg: msg->trx == NULL\n");
		return -EINVAL;
	}

	sign_link = msg->trx->rsl_link;
	msgb_enqueue(&sign_link->tx_list, msg);

	/* notify the driver we have something to write */
	e1inp_driver = sign_link->ts->line->driver;
	e1inp_driver->want_write(sign_link->ts);

	return 0;
}

int _abis_nm_sendmsg(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link;
	struct e1inp_driver *e1inp_driver;

	msg->l2h = msg->data;

	if (!msg->trx || !msg->trx->bts || !msg->trx->bts->oml_link) {
		fprintf(stderr, "nm_sendmsg: msg->trx == NULL\n");
		return -EINVAL;
	}

	sign_link = msg->trx->bts->oml_link;
	msgb_enqueue(&sign_link->tx_list, msg);

	/* notify the driver we have something to write */
	e1inp_driver = sign_link->ts->line->driver;
	e1inp_driver->want_write(sign_link->ts);

	return 0;
}

/* Timeslot */

/* configure and initialize one e1inp_ts */
int e1inp_ts_config(struct e1inp_ts *ts, struct e1inp_line *line,
		    enum e1inp_ts_type type)
{
	ts->type = type;
	ts->line = line;

	switch (type) {
	case E1INP_TS_TYPE_SIGN:
		INIT_LLIST_HEAD(&ts->sign.sign_links);
		break;
	case E1INP_TS_TYPE_TRAU:
		subchan_mux_init(&ts->trau.mux);
		ts->trau.demux.out_cb = subch_cb;
		ts->trau.demux.data = ts;
		subch_demux_init(&ts->trau.demux);
		break;
	default:
		fprintf(stderr, "unsupported E1 timeslot type %u\n",
			ts->type);
		return -EINVAL;
	}
	return 0;
}

static struct e1inp_line *e1inp_line_get(u_int8_t e1_nr)
{
	struct e1inp_line *e1i_line;

	/* iterate over global list of e1 lines */
	llist_for_each_entry(e1i_line, &line_list, list) {
		if (e1i_line->num == e1_nr)
			return e1i_line;
	}
	return NULL;
}

static struct e1inp_ts *e1inp_ts_get(u_int8_t e1_nr, u_int8_t ts_nr)
{
	struct e1inp_line *e1i_line;

	e1i_line = e1inp_line_get(e1_nr);
	if (!e1i_line)
		return NULL;

	return &e1i_line->ts[ts_nr-1];
}

struct subch_mux *e1inp_get_mux(u_int8_t e1_nr, u_int8_t ts_nr)
{
	struct e1inp_ts *e1i_ts = e1inp_ts_get(e1_nr, ts_nr);

	if (!e1i_ts)
		return NULL;

	return &e1i_ts->trau.mux;
}

/* Signalling Link */

struct e1inp_sign_link *e1inp_lookup_sign_link(struct e1inp_ts *e1i,
					 	u_int8_t tei, u_int8_t sapi)
{
	struct e1inp_sign_link *link;

	llist_for_each_entry(link, &e1i->sign.sign_links, list) {
		if (link->sapi == sapi && link->tei == tei)
			return link;
	}

	return NULL;
}

/* create a new signalling link in a E1 timeslot */

struct e1inp_sign_link *
e1inp_sign_link_create(struct e1inp_ts *ts, enum e1inp_sign_type type,
			struct gsm_bts_trx *trx, u_int8_t tei,
			u_int8_t sapi)
{
	struct e1inp_sign_link *link;

	if (ts->type != E1INP_TS_TYPE_SIGN)
		return NULL;

	link = malloc(sizeof(*link));
	if (!link)
		return NULL;

	memset(link, 0, sizeof(*link));

	link->ts = ts;
	link->type = type;
	INIT_LLIST_HEAD(&link->tx_list);
	link->trx = trx;
	link->tei = tei;
	link->sapi = sapi;

	llist_add_tail(&link->list, &ts->sign.sign_links);

	return link;
}

/* the E1 driver tells us he has received something on a TS */
int e1inp_rx_ts(struct e1inp_ts *ts, struct msgb *msg,
		u_int8_t tei, u_int8_t sapi)
{
	struct e1inp_sign_link *link;
	int ret;

	switch (ts->type) {
	case E1INP_TS_TYPE_SIGN:
		/* FIXME: write pcap packet */
		/* consult the list of signalling links */
		link = e1inp_lookup_sign_link(ts, tei, sapi);
		if (!link) {
			fprintf(stderr, "didn't find singalling link for "
				"tei %d, sapi %d\n", tei, sapi);
			return -EINVAL;
		}
		switch (link->type) {
		case E1INP_SIGN_OML:
			msg->trx = link->trx;
			ret = abis_nm_rcvmsg(msg);
			break;
		case E1INP_SIGN_RSL:
			msg->trx = link->trx;
			ret = abis_rsl_rcvmsg(msg);
			break;
		default:
			ret = -EINVAL;
			fprintf(stderr, "unknown link type %u\n", link->type);
			break;
		}
		break;
	case E1INP_TS_TYPE_TRAU:
		ret = subch_demux_in(&ts->trau.demux, msg->data, msg->len);
		break;
	default:
		ret = -EINVAL;
		fprintf(stderr, "unknown TS type %u\n", ts->type);
		break;
	}

	return ret;
}

#define TSX_ALLOC_SIZE 4096

/* called by driver if it wants to transmit on a given TS */
struct msgb *e1inp_tx_ts(struct e1inp_ts *e1i_ts,
			 struct e1inp_sign_link **sign_link)
{
	struct e1inp_sign_link *link;
	struct msgb *msg = NULL;
	int len;

	switch (e1i_ts->type) {
	case E1INP_TS_TYPE_SIGN:
		/* FIXME: implement this round robin */
		llist_for_each_entry(link, &e1i_ts->sign.sign_links, list) {
			msg = msgb_dequeue(&link->tx_list);
			if (msg) {
				if (sign_link)
					*sign_link = link;
				break;
			}
		}
		break;
	case E1INP_TS_TYPE_TRAU:
		msg = msgb_alloc(TSX_ALLOC_SIZE);
		if (!msg)
			return NULL;
		len = subchan_mux_out(&e1i_ts->trau.mux, msg->data, 40);
		msgb_put(msg, 40);
		break;
	default:
		fprintf(stderr, "unsupported E1 TS type %u\n", e1i_ts->type);
		return NULL;
	}
	return msg;
}

/* called by driver in case some kind of link state event */
int e1inp_event(struct e1inp_ts *ts, int evt, u_int8_t tei, u_int8_t sapi)
{
	struct e1inp_sign_link *link;

	link = e1inp_lookup_sign_link(ts, tei, sapi);
	if (!link)
		return -EINVAL;

	/* FIXME: report further upwards */
	return input_event(evt, link->type, link->trx);
}

/* register a driver with the E1 core */
int e1inp_driver_register(struct e1inp_driver *drv)
{
	llist_add_tail(&drv->list, &driver_list);
	return 0;
}

/* register a line with the E1 core */
int e1inp_line_register(struct e1inp_line *line)
{
	int i;

	for (i = 0; i < NUM_E1_TS; i++)
		line->ts[i].num = i+1;

	llist_add_tail(&line->list, &line_list);
	
	return 0;
}