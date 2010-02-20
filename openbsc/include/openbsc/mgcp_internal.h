/* MGCP Private Data */

/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#ifndef OPENBSC_MGCP_DATA_H
#define OPENBSC_MGCP_DATA_H

#include "select.h"

#define CI_UNUSED 0

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

	/* backpointer */
	struct mgcp_config *cfg;
};

#define ENDPOINT_NUMBER(endp) abs(endp - endp->cfg->endpoints)

#endif
