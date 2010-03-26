/* RTP proxy handling for ip.access nanoBTS */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>    /* gettimeofday() */
#include <unistd.h>      /* get..() */
#include <time.h>        /* clock() */
#include <sys/utsname.h> /* uname() */

#include <openbsc/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/msgb.h>
#include <openbsc/select.h>
#include <openbsc/debug.h>
#include <openbsc/rtp_proxy.h>

static LLIST_HEAD(rtp_sockets);

/* should we mangle the CNAME inside SDES of RTCP packets? We disable
 * this by default, as it seems to be not needed */
static int mangle_rtcp_cname = 0;

enum rtp_bfd_priv {
	RTP_PRIV_NONE,
	RTP_PRIV_RTP,
	RTP_PRIV_RTCP
};

#define RTP_ALLOC_SIZE	1500

/* according to RFC 1889 */
struct rtcp_hdr {
	u_int8_t byte0;
	u_int8_t type;
	u_int16_t length;
} __attribute__((packed));

#define RTCP_TYPE_SDES	202
	
#define RTCP_IE_CNAME	1

/* according to RFC 3550 */
struct rtp_hdr {
	u_int8_t  csrc_count:4,
		  extension:1,
		  padding:1,
		  version:2;
	u_int8_t  payload_type:7,
		  marker:1;
	u_int16_t sequence;
	u_int32_t timestamp;
	u_int32_t ssrc;
} __attribute__((packed));

struct rtp_x_hdr {
	u_int16_t by_profile;
	u_int16_t length;
} __attribute__((packed));

#define RTP_VERSION	2

#define RTP_PT_GSM_FULL	3
#define RTP_PT_GSM_EFR	97

/* decode an rtp frame and create a new buffer with payload */
static int rtp_decode(struct msgb *msg, u_int32_t callref, struct msgb **data)
{
	struct msgb *new_msg;
	struct gsm_data_frame *frame;
	struct rtp_hdr *rtph = (struct rtp_hdr *)msg->data;
	struct rtp_x_hdr *rtpxh;
	u_int8_t *payload;
	int payload_len;
	int msg_type;
	int x_len;

	if (msg->len < 12) {
		DEBUGPC(DMUX, "received RTP frame too short (len = %d)\n",
			msg->len);
		return -EINVAL;
	}
	if (rtph->version != RTP_VERSION) {
		DEBUGPC(DMUX, "received RTP version %d not supported.\n",
			rtph->version);
		return -EINVAL;
	}
	payload = msg->data + sizeof(struct rtp_hdr) + (rtph->csrc_count << 2);
	payload_len = msg->len - sizeof(struct rtp_hdr) - (rtph->csrc_count << 2);
	if (payload_len < 0) {
		DEBUGPC(DMUX, "received RTP frame too short (len = %d, "
			"csrc count = %d)\n", msg->len, rtph->csrc_count);
		return -EINVAL;
	}
	if (rtph->extension) {
		if (payload_len < sizeof(struct rtp_x_hdr)) {
			DEBUGPC(DMUX, "received RTP frame too short for "
				"extension header\n");
			return -EINVAL;
		}
		rtpxh = (struct rtp_x_hdr *)payload;
		x_len = ntohs(rtpxh->length) * 4 + sizeof(struct rtp_x_hdr);
		payload += x_len;
		payload_len -= x_len;
		if (payload_len < 0) {
			DEBUGPC(DMUX, "received RTP frame too short, "
				"extension header exceeds frame length\n");
			return -EINVAL;
		}
	}
	if (rtph->padding) {
		if (payload_len < 0) {
			DEBUGPC(DMUX, "received RTP frame too short for "
				"padding length\n");
			return -EINVAL;
		}
		payload_len -= payload[payload_len - 1];
		if (payload_len < 0) {
			DEBUGPC(DMUX, "received RTP frame with padding "
				"greater than payload\n");
			return -EINVAL;
		}
	}

	switch (rtph->payload_type) {
	case RTP_PT_GSM_FULL:
		msg_type = GSM_TCHF_FRAME;
		if (payload_len != 33) {
			DEBUGPC(DMUX, "received RTP full rate frame with "
				"payload length != 32 (len = %d)\n",
				payload_len);
			return -EINVAL;
		}
		break;
	case RTP_PT_GSM_EFR:
		msg_type = GSM_TCHF_FRAME_EFR;
		break;
	default:
		DEBUGPC(DMUX, "received RTP frame with unknown payload "
			"type %d\n", rtph->payload_type);
		return -EINVAL;
	}

	new_msg = msgb_alloc(sizeof(struct gsm_data_frame) + payload_len,
				"GSM-DATA");
	if (!new_msg)
		return -ENOMEM;
	frame = (struct gsm_data_frame *)(new_msg->data);
	frame->msg_type = msg_type;
	frame->callref = callref;
	memcpy(frame->data, payload, payload_len);
	msgb_put(new_msg, sizeof(struct gsm_data_frame) + payload_len);

	*data = new_msg;
	return 0;
}

/* "to - from" */
static void tv_difference(struct timeval *diff, const struct timeval *from,
			  const struct timeval *__to)
{
	struct timeval _to = *__to, *to = &_to;

	if (to->tv_usec < from->tv_usec) {
		to->tv_sec -= 1;
		to->tv_usec += 1000000;
	}

	diff->tv_usec = to->tv_usec - from->tv_usec;
	diff->tv_sec = to->tv_sec - from->tv_sec;
}

/* encode and send a rtp frame */
int rtp_send_frame(struct rtp_socket *rs, struct gsm_data_frame *frame)
{
	struct rtp_sub_socket *rss = &rs->rtp;
	struct msgb *msg;
	struct rtp_hdr *rtph;
	int payload_type;
	int payload_len;
	int duration; /* in samples */

	if (rs->tx_action != RTP_SEND_DOWNSTREAM) {
		/* initialize sequences */
		rs->tx_action = RTP_SEND_DOWNSTREAM;
		rs->transmit.ssrc = rand();
		rs->transmit.sequence = random();
		rs->transmit.timestamp = random();
	}

	switch (frame->msg_type) {
	case GSM_TCHF_FRAME:
		payload_type = RTP_PT_GSM_FULL;
		payload_len = 33;
		duration = 160;
		break;
	case GSM_TCHF_FRAME_EFR:
		payload_type = RTP_PT_GSM_EFR;
		payload_len = 31;
		duration = 160;
		break;
	default:
		DEBUGPC(DMUX, "unsupported message type %d\n",
			frame->msg_type);
		return -EINVAL;
	}

	{
		struct timeval tv, tv_diff;
		long int usec_diff, frame_diff;

		gettimeofday(&tv, NULL);
		tv_difference(&tv_diff, &rs->transmit.last_tv, &tv);
		rs->transmit.last_tv = tv;

		usec_diff = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
		frame_diff = (usec_diff / 20000);

		if (abs(frame_diff) > 1) {
			long int frame_diff_excess = frame_diff - 1;

			LOGP(DMUX, LOGL_NOTICE,
				"Correcting frame difference of %ld frames\n", frame_diff_excess);
			rs->transmit.sequence += frame_diff_excess;
			rs->transmit.timestamp += frame_diff_excess * duration;
		}
	}

	msg = msgb_alloc(sizeof(struct rtp_hdr) + payload_len, "RTP-GSM-FULL");
	if (!msg)
		return -ENOMEM;
	rtph = (struct rtp_hdr *)msg->data;
	rtph->version = RTP_VERSION;
	rtph->padding = 0;
	rtph->extension = 0;
	rtph->csrc_count = 0;
	rtph->marker = 0;
	rtph->payload_type = payload_type;
	rtph->sequence = htons(rs->transmit.sequence++);
	rtph->timestamp = htonl(rs->transmit.timestamp);
	rs->transmit.timestamp += duration;
	rtph->ssrc = htonl(rs->transmit.ssrc);
	memcpy(msg->data + sizeof(struct rtp_hdr), frame->data, payload_len);
	msgb_put(msg, sizeof(struct rtp_hdr) + payload_len);
	msgb_enqueue(&rss->tx_queue, msg);
	rss->bfd.when |= BSC_FD_WRITE;

	return 0;
}

/* iterate over all chunks in one RTCP message, look for CNAME IEs and
 * replace all of those with 'new_cname' */
static int rtcp_sdes_cname_mangle(struct msgb *msg, struct rtcp_hdr *rh,
				  u_int16_t *rtcp_len, const char *new_cname)
{
	u_int8_t *rtcp_end;
	u_int8_t *cur = (u_int8_t *) rh;
	u_int8_t tag, len = 0;

	rtcp_end = cur + *rtcp_len;
	/* move cur to end of RTP header */
	cur += sizeof(*rh);

	/* iterate over Chunks */
	while (cur+4 < rtcp_end) {
		/* skip four bytes SSRC/CSRC */
		cur += 4;
	
		/* iterate over IE's inside the chunk */
		while (cur+1 < rtcp_end) {
			tag = *cur++;
			if (tag == 0) {
				/* end of chunk, skip additional zero */
				while (*cur++ == 0) { }
				break;
			}
			len = *cur++;
	
			if (tag == RTCP_IE_CNAME) {
				/* we've found the CNAME, lets mangle it */
				if (len < strlen(new_cname)) {
					/* we need to make more space */
					int increase = strlen(new_cname) - len;

					msgb_push(msg, increase);
					memmove(cur+len+increase, cur+len,
						rtcp_end - (cur+len));
					/* FIXME: we have to respect RTCP
					 * padding/alignment rules! */
					len += increase;
					*(cur-1) += increase;
					rtcp_end += increase;
					*rtcp_len += increase;
				}
				/* copy new CNAME into message */
				memcpy(cur, new_cname, strlen(new_cname));
				/* FIXME: zero the padding in case new CNAME
				 * is smaller than old one !!! */
			}
			cur += len;
		}
	}

	return 0;
}

static int rtcp_mangle(struct msgb *msg, struct rtp_socket *rs)
{
	struct rtp_sub_socket *rss = &rs->rtcp;
	struct rtcp_hdr *rtph;
	u_int16_t old_len;
	int rc;

	if (!mangle_rtcp_cname)
		return 0;

	printf("RTCP\n");
	/* iterate over list of RTCP messages */
	rtph = (struct rtcp_hdr *)msg->data;
	while ((void *)rtph + sizeof(*rtph) <= (void *)msg->data + msg->len) {
		old_len = (ntohs(rtph->length) + 1) * 4;
		if ((void *)rtph + old_len > (void *)msg->data + msg->len) {
			DEBUGPC(DMUX, "received RTCP packet too short for "
				"length element\n");
			return -EINVAL;
		}
		if (rtph->type == RTCP_TYPE_SDES) {
			char new_cname[255];
			strncpy(new_cname, inet_ntoa(rss->sin_local.sin_addr),
				sizeof(new_cname));
			new_cname[sizeof(new_cname)-1] = '\0';
			rc = rtcp_sdes_cname_mangle(msg, rtph, &old_len,
						    new_cname);
			if (rc < 0)
				return rc;
		}
		rtph = (void *)rtph + old_len;
	}

	return 0;
}

/* read from incoming RTP/RTCP socket */
static int rtp_socket_read(struct rtp_socket *rs, struct rtp_sub_socket *rss)
{
	int rc;
	struct msgb *msg = msgb_alloc(RTP_ALLOC_SIZE, "RTP/RTCP");
	struct msgb *new_msg;
	struct rtp_sub_socket *other_rss;

	if (!msg)
		return -ENOMEM;

	rc = read(rss->bfd.fd, msg->data, RTP_ALLOC_SIZE);
	if (rc <= 0) {
		rss->bfd.when &= ~BSC_FD_READ;
		return rc;
	}

	msgb_put(msg, rc);

	switch (rs->rx_action) {
	case RTP_PROXY:
		if (!rs->proxy.other_sock) {
			rc = -EIO;
			goto out_free;
		}
		if (rss->bfd.priv_nr == RTP_PRIV_RTP)
			other_rss = &rs->proxy.other_sock->rtp;
		else if (rss->bfd.priv_nr == RTP_PRIV_RTCP) {
			other_rss = &rs->proxy.other_sock->rtcp;
			/* modify RTCP SDES CNAME */
			rc = rtcp_mangle(msg, rs);
			if (rc < 0)
				goto out_free;
		} else {
			rc = -EINVAL;
			goto out_free;
		}
		msgb_enqueue(&other_rss->tx_queue, msg);
		other_rss->bfd.when |= BSC_FD_WRITE;
		break;

	case RTP_RECV_UPSTREAM:
		if (!rs->receive.callref || !rs->receive.net) {
			rc = -EIO;
			goto out_free;
		}
		if (rss->bfd.priv_nr == RTP_PRIV_RTCP) {
			if (!mangle_rtcp_cname) {
				msgb_free(msg);
				break;
			}
			/* modify RTCP SDES CNAME */
			rc = rtcp_mangle(msg, rs);
			if (rc < 0)
				goto out_free;
			msgb_enqueue(&rss->tx_queue, msg);
			rss->bfd.when |= BSC_FD_WRITE;
			break;
		}
		if (rss->bfd.priv_nr != RTP_PRIV_RTP) {
			rc = -EINVAL;
			goto out_free;
		}
		rc = rtp_decode(msg, rs->receive.callref, &new_msg);
		if (rc < 0)
			goto out_free;
		msgb_free(msg);
		msgb_enqueue(&rs->receive.net->upqueue, new_msg);
		break;

	case RTP_NONE: /* if socket exists, but disabled by app */
		msgb_free(msg);
		break;
	}

	return 0;

out_free:
	msgb_free(msg);
	return rc;
}

/* write from tx_queue to RTP/RTCP socket */
static int rtp_socket_write(struct rtp_socket *rs, struct rtp_sub_socket *rss)
{
	struct msgb *msg;
	int written;

	msg = msgb_dequeue(&rss->tx_queue);
	if (!msg) {
		rss->bfd.when &= ~BSC_FD_WRITE;
		return 0;
	}

	written = write(rss->bfd.fd, msg->data, msg->len);
	if (written < msg->len) {
		LOGP(DMIB, LOGL_ERROR, "short write");
		msgb_free(msg);
		return -EIO;
	}

	msgb_free(msg);

	return 0;
}


/* callback for the select.c:bfd_* layer */
static int rtp_bfd_cb(struct bsc_fd *bfd, unsigned int flags)
{
	struct rtp_socket *rs = bfd->data;
	struct rtp_sub_socket *rss;

	switch (bfd->priv_nr) {
	case RTP_PRIV_RTP:
		rss = &rs->rtp;
		break;
	case RTP_PRIV_RTCP:
		rss = &rs->rtcp;
		break;
	default:
		return -EINVAL;
	}

	if (flags & BSC_FD_READ)
		rtp_socket_read(rs, rss);

	if (flags & BSC_FD_WRITE)
		rtp_socket_write(rs, rss);

	return 0;
}

static void init_rss(struct rtp_sub_socket *rss, 
		     struct rtp_socket *rs, int fd, int priv_nr)
{
	/* initialize bfd */
	rss->bfd.fd = fd;
	rss->bfd.data = rs;
	rss->bfd.priv_nr = priv_nr;
	rss->bfd.cb = rtp_bfd_cb;
}

struct rtp_socket *rtp_socket_create(void)
{
	int rc;
	struct rtp_socket *rs;

	DEBUGP(DMUX, "rtp_socket_create(): ");

	rs = talloc_zero(tall_bsc_ctx, struct rtp_socket);
	if (!rs)
		return NULL;

	INIT_LLIST_HEAD(&rs->rtp.tx_queue);
	INIT_LLIST_HEAD(&rs->rtcp.tx_queue);

	rc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rc < 0)
		goto out_free;

	init_rss(&rs->rtp, rs, rc, RTP_PRIV_RTP);
	rc = bsc_register_fd(&rs->rtp.bfd);
	if (rc < 0)
		goto out_rtp_socket;

	rc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rc < 0)
		goto out_rtp_bfd;

	init_rss(&rs->rtcp, rs, rc, RTP_PRIV_RTCP);
	rc = bsc_register_fd(&rs->rtcp.bfd);
	if (rc < 0)
		goto out_rtcp_socket;

	DEBUGPC(DMUX, "success\n");

	rc = rtp_socket_bind(rs, INADDR_ANY);
	if (rc < 0)
		goto out_rtcp_bfd;

	return rs;

out_rtcp_bfd:
	bsc_unregister_fd(&rs->rtcp.bfd);
out_rtcp_socket:
	close(rs->rtcp.bfd.fd);
out_rtp_bfd:
	bsc_unregister_fd(&rs->rtp.bfd);
out_rtp_socket:
	close(rs->rtp.bfd.fd);
out_free:
	talloc_free(rs);
	DEBUGPC(DMUX, "failed\n");
	return NULL;
}

static int rtp_sub_socket_bind(struct rtp_sub_socket *rss, u_int32_t ip,
				u_int16_t port)
{
	int rc;
	socklen_t alen = sizeof(rss->sin_local);

	rss->sin_local.sin_family = AF_INET;
	rss->sin_local.sin_addr.s_addr = htonl(ip);
	rss->sin_local.sin_port = htons(port);
	rss->bfd.when |= BSC_FD_READ;

	rc = bind(rss->bfd.fd, (struct sockaddr *)&rss->sin_local,
		  sizeof(rss->sin_local));
	if (rc < 0)
		return rc;

	/* retrieve the address we actually bound to, in case we
	 * passed INADDR_ANY as IP address */
	return getsockname(rss->bfd.fd, (struct sockaddr *)&rss->sin_local,
			   &alen);
}

#define RTP_PORT_BASE	30000
static unsigned int next_udp_port = RTP_PORT_BASE;

/* bind a RTP socket to a local address */
int rtp_socket_bind(struct rtp_socket *rs, u_int32_t ip)
{
	int rc = -EIO;
	struct in_addr ia;

	ia.s_addr = htonl(ip);
	DEBUGP(DMUX, "rtp_socket_bind(rs=%p, IP=%s): ", rs,
		inet_ntoa(ia));

	/* try to bind to a consecutive pair of ports */
	for (next_udp_port = next_udp_port % 0xffff;
	     next_udp_port < 0xffff; next_udp_port += 2) {
		rc = rtp_sub_socket_bind(&rs->rtp, ip, next_udp_port);
		if (rc != 0)
			continue;

		rc = rtp_sub_socket_bind(&rs->rtcp, ip, next_udp_port+1);
		if (rc == 0)
			break;
	}
	if (rc < 0) {
		DEBUGPC(DMUX, "failed\n");
		return rc;
	}

	ia.s_addr = rs->rtp.sin_local.sin_addr.s_addr;
	DEBUGPC(DMUX, "BOUND_IP=%s, BOUND_PORT=%u\n",
		inet_ntoa(ia), ntohs(rs->rtp.sin_local.sin_port));
	return ntohs(rs->rtp.sin_local.sin_port);
}

static int rtp_sub_socket_connect(struct rtp_sub_socket *rss,
				  u_int32_t ip, u_int16_t port)
{
	int rc;
	socklen_t alen = sizeof(rss->sin_local);

	rss->sin_remote.sin_family = AF_INET;
	rss->sin_remote.sin_addr.s_addr = htonl(ip);
	rss->sin_remote.sin_port = htons(port);

	rc = connect(rss->bfd.fd, (struct sockaddr *) &rss->sin_remote,
		     sizeof(rss->sin_remote));
	if (rc < 0)
		return rc;

	return getsockname(rss->bfd.fd, (struct sockaddr *)&rss->sin_local,
			   &alen);
}

/* 'connect' a RTP socket to a remote peer */
int rtp_socket_connect(struct rtp_socket *rs, u_int32_t ip, u_int16_t port)
{
	int rc;
	struct in_addr ia;

	ia.s_addr = htonl(ip);
	DEBUGP(DMUX, "rtp_socket_connect(rs=%p, ip=%s, port=%u)\n",
		rs, inet_ntoa(ia), port);

	rc = rtp_sub_socket_connect(&rs->rtp, ip, port);
	if (rc < 0)
		return rc;

	return rtp_sub_socket_connect(&rs->rtcp, ip, port+1);
}

/* bind two RTP/RTCP sockets together */
int rtp_socket_proxy(struct rtp_socket *this, struct rtp_socket *other)
{
	DEBUGP(DMUX, "rtp_socket_proxy(this=%p, other=%p)\n",
		this, other);

	this->rx_action = RTP_PROXY;
	this->proxy.other_sock = other;

	other->rx_action = RTP_PROXY;
	other->proxy.other_sock = this;

	return 0;
}

/* bind RTP/RTCP socket to application */
int rtp_socket_upstream(struct rtp_socket *this, struct gsm_network *net,
			u_int32_t callref)
{
	DEBUGP(DMUX, "rtp_socket_proxy(this=%p, callref=%u)\n",
		this, callref);

	if (callref) {
		this->rx_action = RTP_RECV_UPSTREAM;
		this->receive.net = net;
		this->receive.callref = callref;
	} else
		this->rx_action = RTP_NONE;

	return 0;
}

static void free_tx_queue(struct rtp_sub_socket *rss)
{
	struct msgb *msg;
	
	while ((msg = msgb_dequeue(&rss->tx_queue)))
		msgb_free(msg);
}

int rtp_socket_free(struct rtp_socket *rs)
{
	DEBUGP(DMUX, "rtp_socket_free(rs=%p)\n", rs);

	/* make sure we don't leave references dangling to us */
	if (rs->rx_action == RTP_PROXY &&
	    rs->proxy.other_sock)
		rs->proxy.other_sock->proxy.other_sock = NULL;

	bsc_unregister_fd(&rs->rtp.bfd);
	close(rs->rtp.bfd.fd);
	free_tx_queue(&rs->rtp);

	bsc_unregister_fd(&rs->rtcp.bfd);
	close(rs->rtcp.bfd.fd);
	free_tx_queue(&rs->rtcp);

	talloc_free(rs);

	return 0;
}
