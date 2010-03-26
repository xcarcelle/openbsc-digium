#ifndef _SUBCH_DEMUX_H
#define _SUBCH_DEMUX_H
/* A E1 sub-channel (de)multiplexer with TRAU frame sync */

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

#include <sys/types.h>
#include <openbsc/linuxlist.h>

#define NR_SUBCH	4
#define TRAU_FRAME_SIZE	40
#define TRAU_FRAME_BITS	(TRAU_FRAME_SIZE*8)

/***********************************************************************/
/* DEMULTIPLEXER */
/***********************************************************************/

struct demux_subch {
	u_int8_t out_bitbuf[TRAU_FRAME_BITS];
	u_int16_t out_idx; /* next bit to be written in out_bitbuf */
	/* number of consecutive zeros that we have received (for sync) */
	unsigned int consecutive_zeros;
	/* are we in TRAU frame sync or not? */
	unsigned int in_sync;
};

struct subch_demux {
	/* bitmask of currently active subchannels */
	u_int8_t chan_activ;
	/* one demux_subch struct for every subchannel */
	struct demux_subch subch[NR_SUBCH];
	/* callback to be called once we have received a complete
	 * frame on a given subchannel */
	int (*out_cb)(struct subch_demux *dmx, int ch, u_int8_t *data, int len,
		      void *);
	/* user-provided data, transparently passed to out_cb() */
	void *data;
};

/* initialize one demultiplexer instance */
int subch_demux_init(struct subch_demux *dmx);

/* feed 'len' number of muxed bytes into the demultiplexer */
int subch_demux_in(struct subch_demux *dmx, u_int8_t *data, int len);

/* activate decoding/processing for one subchannel */
int subch_demux_activate(struct subch_demux *dmx, int subch);

/* deactivate decoding/processing for one subchannel */
int subch_demux_deactivate(struct subch_demux *dmx, int subch);

/***********************************************************************/
/* MULTIPLEXER */
/***********************************************************************/

/* one element in the tx_queue of a muxer sub-channel */
struct subch_txq_entry {
	struct llist_head list;

	unsigned int bit_len;	/* total number of bits in 'bits' */
	unsigned int next_bit;	/* next bit to be transmitted */

	u_int8_t bits[0];	/* one bit per byte */
};

struct mux_subch {
	struct llist_head tx_queue;
};

/* structure representing one instance of the subchannel muxer */
struct subch_mux {
	struct mux_subch subch[NR_SUBCH];
};

/* initialize a subchannel muxer instance */
int subchan_mux_init(struct subch_mux *mx);

/* request the output of 'len' multiplexed bytes */
int subchan_mux_out(struct subch_mux *mx, u_int8_t *data, int len);

/* enqueue some data into one sub-channel of the muxer */
int subchan_mux_enqueue(struct subch_mux *mx, int s_nr, const u_int8_t *data,
			int len);

#endif /* _SUBCH_DEMUX_H */
