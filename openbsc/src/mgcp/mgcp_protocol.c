/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by On-Waves
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openbsc/debug.h>
#include <openbsc/msgb.h>
#include <openbsc/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/select.h>
#include <openbsc/mgcp.h>
#include <openbsc/telnet_interface.h>

#include <vty/command.h>
#include <vty/vty.h>

#warning "Make use of the rtp proxy code"

static int source_port = 2427;
static const char *local_ip = NULL;
static const char *source_addr = "0.0.0.0";
static unsigned int number_endpoints = 0;
static const char *bts_ip = NULL;
static struct in_addr bts_in;
static const char *audio_name = "GSM-EFR/8000";
static int audio_payload = 97;
static int audio_loop = 0;
static int early_bind = 0;

static char *forward_ip = NULL;
static int forward_port = 0;

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
};

enum {
	DEST_NETWORK = 0,
	DEST_BTS = 1,
};

enum {
	PROTO_RTP,
	PROTO_RTCP,
};

#define CI_UNUSED 0
static unsigned int last_call_id = 0;

struct mgcp_endpoint {
	int ci;
	char *callid;
	char *local_options;
	int conn_mode;

	/* the local rtp port we are binding to */
	int rtp_port;

	/*
	 * RTP mangling:
	 *  - we get RTP and RTCP to us and need to forward to the BTS
	 *  - we get RTP and RTCP from the BTS and forward to the network
	 */
	struct bsc_fd local_rtp;
	struct bsc_fd local_rtcp;

	struct in_addr remote;
	struct in_addr bts;

	/* in network byte order */
	int net_rtp, net_rtcp;
	int bts_rtp, bts_rtcp;
};

static struct mgcp_endpoint *endpoints = NULL;
#define ENDPOINT_NUMBER(endp) abs(endp - endpoints)

/**
 * Macro for tokenizing MGCP messages and SDP in one go.
 *
 */
#define MSG_TOKENIZE_START \
	line_start = 0;						\
	for (i = 0; i < msgb_l3len(msg); ++i) {			\
		/* we have a line end */			\
		if (msg->l3h[i] == '\n') {			\
			/* skip the first line */		\
			if (line_start == 0) {			\
				line_start = i + 1;		\
				continue;			\
			}					\
								\
			/* check if we have a proper param */	\
			if (i - line_start == 1 && msg->l3h[line_start] == '\r') { \
			} else if (i - line_start > 2		\
			    && islower(msg->l3h[line_start])	\
			    && msg->l3h[line_start + 1] == '=') { \
			} else if (i - line_start < 3		\
			    || msg->l3h[line_start + 1] != ':'	\
			    || msg->l3h[line_start + 2] != ' ')	\
				goto error;			\
								\
			msg->l3h[i] = '\0';			\
			if (msg->l3h[i-1] == '\r')		\
				msg->l3h[i-1] = '\0';

#define MSG_TOKENIZE_END \
			line_start = i + 1; \
		}			    \
	}


struct mgcp_msg_ptr {
	unsigned int start;
	unsigned int length;
};

struct mgcp_request {
	char *name;
	struct msgb *(*handle_request) (struct msgb *msg);
	char *debug_name;
};

#define MGCP_REQUEST(NAME, REQ, DEBUG_NAME) \
	{ .name = NAME, .handle_request = REQ, .debug_name = DEBUG_NAME },

static struct msgb *handle_audit_endpoint(struct msgb *msg);
static struct msgb *handle_create_con(struct msgb *msg);
static struct msgb *handle_delete_con(struct msgb *msg);
static struct msgb *handle_modify_con(struct msgb *msg);

static mgcp_change change_cb;
static void *change_cb_data;

static int generate_call_id()
{
	int i;

	/* use the call id */
	++last_call_id;

	/* handle wrap around */
	if (last_call_id == CI_UNUSED)
		++last_call_id;

	/* callstack can only be of size number_of_endpoints */
	/* verify that the call id is free, e.g. in case of overrun */
	for (i = 1; i < number_endpoints; ++i)
		if (endpoints[i].ci == last_call_id)
			return generate_call_id();

	return last_call_id;
}

/* FIXIME/TODO: need to have a list of pending transactions and check that */
static unsigned int generate_transaction_id()
{
	return abs(rand());
}

static int udp_send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

/*
 * There is data coming. We will have to figure out if it
 * came from the BTS or the MediaGateway of the MSC. On top
 * of that we need to figure out if it was RTP or RTCP.
 *
 * Currently we do not communicate with the BSC so we have
 * no idea where the BTS is listening for RTP and need to
 * do the classic routing trick. Wait for the first packet
 * from the BTS and then go ahead.
 */
static int rtp_data_cb(struct bsc_fd *fd, unsigned int what)
{
	char buf[4096];
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct mgcp_endpoint *endp;
	int rc, dest, proto;

	endp = (struct mgcp_endpoint *) fd->data;

	rc = recvfrom(fd->fd, &buf, sizeof(buf), 0,
			    (struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to receive message on: 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* do not forward aynthing... maybe there is a packet from the bts */
	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Unknown message on endpoint: 0x%x\n", ENDPOINT_NUMBER(endp));
		return -1;
	}

	/*
	 * Figure out where to forward it to. This code assumes that we
	 * have received the Connection Modify and know who is a legitimate
	 * partner. According to the spec we could attempt to forward even
	 * after the Create Connection but we will not as we are not really
	 * able to tell if this is legitimate.
	 */
	#warning "Slight spec violation. With connection mode recvonly we should attempt to forward."
	dest = memcmp(&addr.sin_addr, &endp->remote, sizeof(addr.sin_addr)) == 0 &&
                    (endp->net_rtp == addr.sin_port || endp->net_rtcp == addr.sin_port)
			? DEST_BTS : DEST_NETWORK;
	proto = fd == &endp->local_rtp ? PROTO_RTP : PROTO_RTCP;

	/* We have no idea who called us, maybe it is the BTS. */
	if (dest == DEST_NETWORK && (endp->bts_rtp == 0 || forward_ip)) {
		/* it was the BTS... */
		if (!bts_ip || memcmp(&addr.sin_addr, &bts_in, sizeof(bts_in)) == 0) {
			if (fd == &endp->local_rtp) {
				endp->bts_rtp = addr.sin_port;
			} else {
				endp->bts_rtcp = addr.sin_port;
			}

			endp->bts = addr.sin_addr;
			LOGP(DMGCP, LOGL_NOTICE, "Found BTS for endpoint: 0x%x on port: %d/%d\n",
				ENDPOINT_NUMBER(endp), ntohs(endp->bts_rtp), ntohs(endp->bts_rtcp));
		}
	}

	/* dispatch */
	if (audio_loop)
		dest = !dest;

	if (dest == DEST_NETWORK) {
		return udp_send(fd->fd, &endp->remote,
			     proto == PROTO_RTP ? endp->net_rtp : endp->net_rtcp,
			     buf, rc);
	} else {
		return udp_send(fd->fd, &endp->bts,
			     proto == PROTO_RTP ? endp->bts_rtp : endp->bts_rtcp,
			     buf, rc);
	}
}

static int create_bind(struct bsc_fd *fd, int port)
{
	struct sockaddr_in addr;
	int on = 1;

	fd->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd->fd < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create UDP port.\n");
		return -1;
	}

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton(source_addr, &addr.sin_addr);

	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		return -1;
	}

	return 0;
}

static int bind_rtp(struct mgcp_endpoint *endp)
{
	if (create_bind(&endp->local_rtp, endp->rtp_port) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create RTP port: %s:%d on 0x%x\n",
		       source_addr, endp->rtp_port, ENDPOINT_NUMBER(endp));
		goto cleanup0;
	}

	if (create_bind(&endp->local_rtcp, endp->rtp_port + 1) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create RTCP port: %s:%d on 0x%x\n",
		       source_addr, endp->rtp_port + 1, ENDPOINT_NUMBER(endp));
		goto cleanup1;
	}

	endp->local_rtp.cb = rtp_data_cb;
	endp->local_rtp.data = endp;
	endp->local_rtp.when = BSC_FD_READ;
	if (bsc_register_fd(&endp->local_rtp) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register RTP port %d on 0x%x\n",
			endp->rtp_port, ENDPOINT_NUMBER(endp));
		goto cleanup2;
	}

	endp->local_rtcp.cb = rtp_data_cb;
	endp->local_rtcp.data = endp;
	endp->local_rtcp.when = BSC_FD_READ;
	if (bsc_register_fd(&endp->local_rtcp) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register RTCP port %d on 0x%x\n",
			endp->rtp_port + 1, ENDPOINT_NUMBER(endp));
		goto cleanup3;
	}

	return 0;

cleanup3:
	bsc_unregister_fd(&endp->local_rtp);
cleanup2:
	close(endp->local_rtcp.fd);
	endp->local_rtcp.fd = -1;
cleanup1:
	close(endp->local_rtp.fd);
	endp->local_rtp.fd = -1;
cleanup0:
	return -1;
}

/*
 * array of function pointers for handling various
 * messages. In the future this might be binary sorted
 * for performance reasons.
 */
static const struct mgcp_request mgcp_requests [] = {
	MGCP_REQUEST("AUEP", handle_audit_endpoint, "AuditEndpoint")
	MGCP_REQUEST("CRCX", handle_create_con, "CreateConnection")
	MGCP_REQUEST("DLCX", handle_delete_con, "DeleteConnection")
	MGCP_REQUEST("MDCX", handle_modify_con, "ModifiyConnection")
};

static struct msgb *mgcp_msgb_alloc(void)
{
	struct msgb *msg;
	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	if (!msg)
	    LOGP(DMGCP, LOGL_ERROR, "Failed to msgb for MGCP data.\n");

	return msg;
}

static struct msgb *send_response_with_data(int code, const char *msg, const char *trans,
				    const char *data)
{
	int len;
	struct msgb *res;

	res = mgcp_msgb_alloc();
	if (!res)
		return NULL;

	if (data) {
		len = snprintf((char *) res->data, 2048, "%d %s\n%s", code, trans, data);
	} else {
		len = snprintf((char *) res->data, 2048, "%d %s\n", code, trans);
	}

	res->l2h = msgb_put(res, len);
	LOGP(DMGCP, LOGL_NOTICE, "Sending response: code: %d for '%s'\n", code, res->l2h);
	return res;
}

static struct msgb *send_response(int code, const char *msg, const char *trans)
{
	return send_response_with_data(code, msg, trans, NULL);
}

static struct msgb *send_with_sdp(struct mgcp_endpoint *endp, const char *msg, const char *trans_id)
{
	const char *addr = local_ip;
	char sdp_record[4096];

	if (!addr)
		addr = source_addr;

	snprintf(sdp_record, sizeof(sdp_record) - 1,
			"I: %d\n\n"
			"v=0\r\n"
			"c=IN IP4 %s\r\n"
			"m=audio %d RTP/AVP %d\r\n"
			"a=rtpmap:%d %s\r\n",
			endp->ci, addr, endp->rtp_port,
			audio_payload, audio_payload, audio_name);
	return send_response_with_data(200, msg, trans_id, sdp_record);
}

/* send a static record */
struct msgb *mgcp_create_rsip(void)
{
	struct msgb *msg;
	int len;

	msg = mgcp_msgb_alloc();
	if (!msg)
		return NULL;

	len = snprintf((char *) msg->data, 2048,
			"RSIP %u *@mgw MGCP 1.0\n"
			"RM: restart\n", generate_transaction_id());
	msg->l2h = msgb_put(msg, len);
	return msg;
}

/*
 * handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id)
 */
struct msgb *mgcp_handle_message(struct msgb *msg)
{
        int code;
	struct msgb *resp = NULL;

	if (msg->len < 4) {
		LOGP(DMGCP, LOGL_ERROR, "mgs too short: %d\n", msg->len);
		return NULL;
	}

        /* attempt to treat it as a response */
        if (sscanf((const char *)&msg->data[0], "%3d %*s", &code) == 1) {
		LOGP(DMGCP, LOGL_NOTICE, "Response: Code: %d\n", code);
	} else {
		int i, handled = 0;
		msg->l3h = &msg->l2h[4];
		for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i)
			if (strncmp(mgcp_requests[i].name, (const char *) &msg->data[0], 4) == 0) {
				handled = 1;
				resp = mgcp_requests[i].handle_request(msg);
				break;
			}
		if (!handled) {
			LOGP(DMGCP, LOGL_NOTICE, "MSG with type: '%.4s' not handled\n", &msg->data[0]);
		}
	}

	return resp;
}

/* string tokenizer for the poor */
static int find_msg_pointers(struct msgb *msg, struct mgcp_msg_ptr *ptrs, int ptrs_length)
{
	int i, found = 0;

	int whitespace = 1;
	for (i = 0; i < msgb_l3len(msg) && ptrs_length > 0; ++i) {
		/* if we have a space we found an end */
		if (msg->l3h[i]	== ' ' || msg->l3h[i] == '\r' || msg->l3h[i] == '\n') {
			if (!whitespace) {
				++found;
				whitespace = 1;
				ptrs->length = i - ptrs->start - 1;
				++ptrs;
				--ptrs_length;
			} else {
			    /* skip any number of whitespace */
			}

			/* line end... stop */
			if (msg->l3h[i] == '\r' || msg->l3h[i] == '\n')
				break;
		} else if (msg->l3h[i] == '\r' || msg->l3h[i] == '\n') {
			/* line end, be done */
			break;
		} else if (whitespace) {
			whitespace = 0;
			ptrs->start = i;
		}
	}

	if (ptrs_length == 0)
		return -1;
	return found;
}

static struct mgcp_endpoint *find_endpoint(const char *mgcp)
{
	char *endptr = NULL;
	unsigned int gw = INT_MAX;

	gw = strtoul(mgcp, &endptr, 16);
	if (gw == 0 || gw >= number_endpoints || strcmp(endptr, "@mgw") != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Not able to find endpoint: '%s'\n", mgcp);
		return NULL;
	}

	return &endpoints[gw];
}

static int analyze_header(struct msgb *msg, struct mgcp_msg_ptr *ptr, int size,
			  const char **transaction_id, struct mgcp_endpoint **endp)
{
	int found;

	if (size < 3) {
		LOGP(DMGCP, LOGL_ERROR, "Not enough space in ptr\n");
		return -1;
	}

	found = find_msg_pointers(msg, ptr, size);

	if (found < 3) {
		LOGP(DMGCP, LOGL_ERROR, "Gateway: Not enough params. Found: %d\n", found);
		return -1;
	}

	/*
	 * replace the space with \0. the main method gurantess that
	 * we still have + 1 for null termination
	 */
	msg->l3h[ptr[3].start + ptr[3].length + 1] = '\0';
	msg->l3h[ptr[2].start + ptr[2].length + 1] = '\0';
	msg->l3h[ptr[1].start + ptr[1].length + 1] = '\0';
	msg->l3h[ptr[0].start + ptr[0].length + 1] = '\0';

	if (strncmp("1.0", (const char *)&msg->l3h[ptr[3].start], 3) != 0
	    || strncmp("MGCP", (const char *)&msg->l3h[ptr[2].start], 4) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Wrong MGCP version. Not handling: '%s' '%s'\n",
			(const char *)&msg->l3h[ptr[3].start],
			(const char *)&msg->l3h[ptr[2].start]);
		return -1;
	}

	*transaction_id = (const char *)&msg->l3h[ptr[0].start];
	*endp = find_endpoint((const char *)&msg->l3h[ptr[1].start]);
	return *endp == NULL;
}

static int verify_call_id(const struct mgcp_endpoint *endp,
			  const char *callid)
{
	if (strcmp(endp->callid, callid) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "CallIDs does not match on 0x%x. '%s' != '%s'\n",
			ENDPOINT_NUMBER(endp), endp->callid, callid);
		return -1;
	}

	return 0;
}

static int verify_ci(const struct mgcp_endpoint *endp,
		     const char *ci)
{
	if (atoi(ci) != endp->ci) {
		LOGP(DMGCP, LOGL_ERROR, "ConnectionIdentifiers do not match on 0x%x. %d != %s\n",
			ENDPOINT_NUMBER(endp), endp->ci, ci);
		return -1;
	}

	return 0;
}

static struct msgb *handle_audit_endpoint(struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, response;
	const char *trans_id;
	struct mgcp_endpoint *endp;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
	    response = 500;
	else
	    response = 200;

	return send_response(response, "AUEP", trans_id);
}

static int parse_conn_mode(const char* msg, int *conn_mode)
{
	int ret = 0;
	if (strcmp(msg, "recvonly") == 0)
		*conn_mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(msg, "sendrecv") == 0)
		*conn_mode = MGCP_CONN_RECV_SEND;
	else {
		LOGP(DMGCP, LOGL_ERROR, "Unknown connection mode: '%s'\n", msg);
		ret = -1;
	}

	return ret;
}

static struct msgb *handle_create_con(struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return send_response(500, "CRCX", trans_id);

	if (endp->ci != CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is already used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return send_response(500, "CRCX", trans_id);
	}

	/* parse CallID C: and LocalParameters L: */
	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'L':
		endp->local_options = talloc_strdup(endpoints,
			(const char *)&msg->l3h[line_start + 3]);
		break;
	case 'C':
		endp->callid = talloc_strdup(endpoints,
			(const char *)&msg->l3h[line_start + 3]);
		break;
	case 'M':
		if (parse_conn_mode((const char *)&msg->l3h[line_start + 3],
			    &endp->conn_mode) != 0) {
		    error_code = 517;
		    goto error2;
		}
		break;
	default:
		LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END

	/* initialize */
	endp->net_rtp = endp->net_rtcp = endp->bts_rtp = endp->bts_rtcp = 0;

	/* set to zero until we get the info */
	memset(&endp->remote, 0, sizeof(endp->remote));

	/* bind to the port now */
	endp->rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp), rtp_base_port);
	if (!early_bind && bind_rtp(endp) != 0)
		goto error2;

	/* assign a local call identifier or fail */
	endp->ci = generate_call_id();
	if (endp->ci == CI_UNUSED)
		goto error2;

	LOGP(DMGCP, LOGL_NOTICE, "Creating endpoint on: 0x%x CI: %u port: %u\n",
		ENDPOINT_NUMBER(endp), endp->ci, endp->rtp_port);
	if (change_cb)
		change_cb(ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX, endp->rtp_port, change_cb_data);

	return send_with_sdp(endp, "CRCX", trans_id);
error:
	LOGP(DMGCP, LOGL_ERROR, "Malformed line: %s on 0x%x with: line_start: %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i);
	return send_response(error_code, "CRCX", trans_id);

error2:
	LOGP(DMGCP, LOGL_NOTICE, "Resource error on 0x%x\n", ENDPOINT_NUMBER(endp));
	return send_response(error_code, "CRCX", trans_id);
}

static struct msgb *handle_modify_con(struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return send_response(error_code, "MDCX", trans_id);

	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not holding a connection. 0x%x\n", ENDPOINT_NUMBER(endp));
		return send_response(error_code, "MDCX", trans_id);
	}

	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'C': {
		if (verify_call_id(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	case 'I': {
		if (verify_ci(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	case 'L':
		/* skip */
		break;
	case 'M':
		if (parse_conn_mode((const char *)&msg->l3h[line_start + 3],
			    &endp->conn_mode) != 0) {
		    error_code = 517;
		    goto error3;
		}
		break;
	case '\0':
		/* SDP file begins */
		break;
	case 'a':
	case 'o':
	case 's':
	case 't':
	case 'v':
		/* skip these SDP attributes */
		break;
	case 'm': {
		int port;
		const char *param = (const char *)&msg->l3h[line_start];

		if (sscanf(param, "m=audio %d RTP/AVP %*d", &port) == 1) {
			endp->net_rtp = htons(port);
			endp->net_rtcp = htons(port + 1);
		}
		break;
	}
	case 'c': {
		char ipv4[16];
		const char *param = (const char *)&msg->l3h[line_start];

		if (sscanf(param, "c=IN IP4 %15s", ipv4) == 1) {
			inet_aton(ipv4, &endp->remote);
		}
		break;
	}
	default:
		LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END

	/* modify */
	LOGP(DMGCP, LOGL_NOTICE, "Modified endpoint on: 0x%x Server: %s:%u\n",
		ENDPOINT_NUMBER(endp), inet_ntoa(endp->remote), endp->net_rtp);
	if (change_cb)
		change_cb(ENDPOINT_NUMBER(endp), MGCP_ENDP_MDCX, endp->rtp_port, change_cb_data);
	return send_with_sdp(endp, "MDCX", trans_id);

error:
	LOGP(DMGCP, LOGL_ERROR, "Malformed line: %s on 0x%x with: line_start: %d %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i, msg->l3h[line_start]);
	return send_response(error_code, "MDCX", trans_id);

error3:
	return send_response(error_code, "MDCX", trans_id);
}

static struct msgb *handle_delete_con(struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return send_response(error_code, "DLCX", trans_id);

	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return send_response(error_code, "DLCX", trans_id);
	}

	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'C': {
		if (verify_call_id(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	case 'I': {
		if (verify_ci(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	default:
		LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END


	/* free the connection */
	LOGP(DMGCP, LOGL_NOTICE, "Deleting endpoint on: 0x%x\n", ENDPOINT_NUMBER(endp));
	endp->ci= CI_UNUSED;
	talloc_free(endp->callid);
	talloc_free(endp->local_options);

	if (!early_bind) {
		bsc_unregister_fd(&endp->local_rtp);
		bsc_unregister_fd(&endp->local_rtcp);
	}

	endp->net_rtp = endp->net_rtcp = endp->bts_rtp = endp->bts_rtcp = 0;
	if (change_cb)
		change_cb(ENDPOINT_NUMBER(endp), MGCP_ENDP_DLCX, endp->rtp_port, change_cb_data);

	return send_response(250, "DLCX", trans_id);

error:
	LOGP(DMGCP, LOGL_ERROR, "Malformed line: %s on 0x%x with: line_start: %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i);
	return send_response(error_code, "DLCX", trans_id);

error3:
	return send_response(error_code, "DLCX", trans_id);
}

/*
 * vty code for mgcp below
 */
struct cmd_node mgcp_node = {
	MGCP_NODE,
	"%s(mgcp)#",
	1,
};

static int config_write_mgcp(struct vty *vty)
{
	vty_out(vty, "mgcp%s", VTY_NEWLINE);
	if (local_ip)
		vty_out(vty, " local ip %s%s", local_ip, VTY_NEWLINE);
	if (bts_ip)
		vty_out(vty, "  bts ip %s%s", bts_ip, VTY_NEWLINE);
	vty_out(vty, "  bind ip %s%s", source_addr, VTY_NEWLINE);
	vty_out(vty, "  bind port %u%s", source_port, VTY_NEWLINE);
	vty_out(vty, "  bind early %u%s", !!early_bind, VTY_NEWLINE);
	vty_out(vty, "  rtp base %u%s", rtp_base_port, VTY_NEWLINE);
	vty_out(vty, "  sdp audio payload number %u%s", audio_payload, VTY_NEWLINE);
	vty_out(vty, "  sdp audio payload name %s%s", audio_name, VTY_NEWLINE);
	vty_out(vty, "  loop %u%s", !!audio_loop, VTY_NEWLINE);
	vty_out(vty, "  endpoints %u%s", number_endpoints, VTY_NEWLINE);
	if (forward_ip)
		vty_out(vty, " forward audio ip %s%s", forward_ip, VTY_NEWLINE);
	if (forward_port != 0)
		vty_out(vty, " forward audio port %d%s", forward_port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(show_mcgp, show_mgcp_cmd, "show mgcp",
      SHOW_STR "Display information about the MGCP Media Gateway")
{
	int i;

	vty_out(vty, "MGCP is up and running with %u endpoints:%s", number_endpoints - 1, VTY_NEWLINE);
	for (i = 1; i < number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &endpoints[i];
		vty_out(vty, " Endpoint 0x%.2x: CI: %d net: %u/%u bts: %u/%u%s",
			i, endp->ci,
			ntohs(endp->net_rtp), ntohs(endp->net_rtcp),
			ntohs(endp->bts_rtp), ntohs(endp->bts_rtcp), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp,
      cfg_mgcp_cmd,
      "mgcp",
      "Configure the MGCP")
{
	vty->node = MGCP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_local_ip,
      cfg_mgcp_local_ip_cmd,
      "local ip IP",
      "Set the IP to be used in SDP records")
{
	local_ip = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bts_ip,
      cfg_mgcp_bts_ip_cmd,
      "bts ip IP",
      "Set the IP of the BTS for RTP forwarding")
{
	bts_ip = talloc_strdup(tall_bsc_ctx, argv[0]);
	inet_aton(bts_ip, &bts_in);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_ip,
      cfg_mgcp_bind_ip_cmd,
      "bind ip IP",
      "Bind the MGCP to this local addr")
{
	source_addr = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_port,
      cfg_mgcp_bind_port_cmd,
      "bind port <0-65534>",
      "Bind the MGCP to this port")
{
	unsigned int port = atoi(argv[0]);
	if (port > 65534) {
		vty_out(vty, "%% wrong bind port '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	source_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_early,
      cfg_mgcp_bind_early_cmd,
      "bind early (0|1)",
      "Bind all RTP ports early")
{
	unsigned int bind = atoi(argv[0]);
	if (bind != 0 && bind != 1) {
		vty_out(vty, "%% param must be 0 or 1.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	early_bind = bind == 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_base_port,
      cfg_mgcp_rtp_base_port_cmd,
      "rtp base <0-65534>",
      "Base port to use")
{
	unsigned int port = atoi(argv[0]);
	if (port > 65534) {
		vty_out(vty, "%% wrong base port '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rtp_base_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_sdp_payload_number,
      cfg_mgcp_sdp_payload_number_cmd,
      "sdp audio payload number <1-255>",
      "Set the audio codec to use")
{
	unsigned int payload = atoi(argv[0]);
	if (payload > 255) {
		vty_out(vty, "%% wrong payload number '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	audio_payload = payload;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_sdp_payload_name,
      cfg_mgcp_sdp_payload_name_cmd,
      "sdp audio payload name NAME",
      "Set the audio name to use")
{
	audio_name = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_loop,
      cfg_mgcp_loop_cmd,
      "loop (0|1)",
      "Loop the audio")
{
	audio_loop = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_number_endp,
      cfg_mgcp_number_endp_cmd,
      "number endpoints <0-65534>",
      "The number of endpoints to allocate. This is not dynamic.")
{
	/* + 1 as we start counting at one */
	number_endpoints = atoi(argv[0]) + 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_forward_ip,
      cfg_mgcp_forward_ip_cmd,
      "forward audio ip IP",
      "Forward packets from and to the IP. This disables most of the MGCP feature.")
{
	if (forward_ip)
		talloc_free(forward_ip);
	forward_ip = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_forward_port,
      cfg_mgcp_forward_port_cmd,
      "forward audio port <1-15000>",
      "Forward packets from and to the port. This disables most of the MGCP feature.")
{
	forward_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

int mgcp_vty_init(void)
{
	install_element(VIEW_NODE, &show_mgcp_cmd);

	install_element(CONFIG_NODE, &cfg_mgcp_cmd);
	install_node(&mgcp_node, config_write_mgcp);
	install_default(MGCP_NODE);
	install_element(MGCP_NODE, &cfg_mgcp_local_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bts_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_early_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_base_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_loop_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_number_endp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_forward_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_forward_port_cmd);
	return 0;
}

int mgcp_parse_config(const char *config_file, struct gsm_network *dummy_network)
{
	int i, rc;

	rc = vty_read_config_file(config_file);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}


	if (!bts_ip)
		fprintf(stderr, "No BTS ip address specified. This will allow everyone to connect.\n");

	endpoints = _talloc_zero_array(tall_bsc_ctx,
				       sizeof(struct mgcp_endpoint),
				       number_endpoints, "endpoints");
	if (!endpoints) {
		fprintf(stderr, "Failed to allocate endpoints: %d. Quitting.\n", number_endpoints);
		return -1;
	}

	/* Initialize all endpoints */
	for (i = 0; i < number_endpoints; ++i) {
		endpoints[i].local_rtp.fd = -1;
		endpoints[i].local_rtcp.fd = -1;
		endpoints[i].ci = CI_UNUSED;
	}

	/*
	 * This application supports two modes.
         *    1.) a true MGCP gateway with support for AUEP, CRCX, MDCX, DLCX
         *    2.) plain forwarding of RTP packets on the endpoints.
	 * both modes are mutual exclusive
	 */
	if (forward_ip) {
		int port = rtp_base_port;
		if (forward_port != 0)
			port = forward_port;

		if (!early_bind) {
			LOGP(DMGCP, LOGL_NOTICE, "Forwarding requires early bind.\n");
			return -1;
		}

		/*
		 * Store the forward IP and assign a ci. For early bind
		 * the sockets will be created after this.
		 */
		for (i = 1; i < number_endpoints; ++i) {
			struct mgcp_endpoint *endp = &endpoints[i];
			inet_aton(forward_ip, &endp->remote);
			endp->ci = CI_UNUSED + 23;
			endp->net_rtp = htons(rtp_calculate_port(ENDPOINT_NUMBER(endp), port));
			endp->net_rtcp = htons(rtp_calculate_port(ENDPOINT_NUMBER(endp), port) + 1);
		}

		LOGP(DMGCP, LOGL_NOTICE, "Configured for Audio Forwarding.\n");
	}

	/* early bind */
	if (early_bind) {
		for (i = 1; i < number_endpoints; ++i) {
			struct mgcp_endpoint *endp = &endpoints[i];
			endp->rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp), rtp_base_port);
			if (bind_rtp(endp) != 0) {
				LOGP(DMGCP, LOGL_FATAL, "Failed to bind: %d\n", endp->rtp_port);
				return -1;
			}
		}
	}

	return !!forward_ip;
}

void mgcp_set_change_cb(mgcp_change cb, void *data)
{
	change_cb = cb;
	change_cb_data = data;
}
