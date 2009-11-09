/* Management functions to allocate/release struct gsm_lchan */
/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#ifndef _CHAN_ALLOC_H
#define _CHAN_ALLOC_H

#include "gsm_subscriber.h"

/* Special allocator for C0 of BTS */
struct gsm_bts_trx_ts *ts_c0_alloc(struct gsm_bts *bts,
				   enum gsm_phys_chan_config pchan);

/* Regular physical channel allocator */
struct gsm_bts_trx_ts *ts_alloc(struct gsm_bts *bts,
				enum gsm_phys_chan_config pchan);

/* Regular physical channel (TS) */
void ts_free(struct gsm_bts_trx_ts *ts);

/* Find an allocated channel */
struct gsm_lchan *lchan_find(struct gsm_bts *bts, struct gsm_subscriber *subscr);

/* Find an allocated channel for a specified subscriber */
struct gsm_lchan *lchan_for_subscr(struct gsm_subscriber *subscr);

/* Allocate a logical channel (SDCCH, TCH, ...) */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type);

/* Free a logical channel (SDCCH, TCH, ...) */
void lchan_free(struct gsm_lchan *lchan);

/* Consider releasing the channel */
int lchan_auto_release(struct gsm_lchan *lchan);

/* Claim a channel by a GSM subscriber:
 *   - this adds the refcount
 */
int lchan_claim_channel(struct gsm_lchan *lchan, struct gsm_subscriber *subsr);

#endif /* _CHAN_ALLOC_H */
