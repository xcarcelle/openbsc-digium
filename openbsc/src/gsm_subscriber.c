/* The concept of a subscriber for the MSC, roughly HLR/VLR functionality */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/db.h>

extern struct llist_head *subscr_bsc_active_subscriber(void);

struct gsm_subscriber *subscr_get_by_tmsi(const char *tmsi)
{
	struct gsm_subscriber *subscr;

	/* we might have a record in memory already */
	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (strcmp(subscr->tmsi, tmsi) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(GSM_SUBSCRIBER_TMSI, tmsi);
}

struct gsm_subscriber *subscr_get_by_imsi(const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (strcmp(subscr->imsi, imsi) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(GSM_SUBSCRIBER_IMSI, imsi);
}

struct gsm_subscriber *subscr_get_by_extension(const char *ext)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (strcmp(subscr->extension, ext) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(GSM_SUBSCRIBER_EXTENSION, ext);
}

int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason)
{
	/* FIXME: Migrate pending requests from one BSC to another */
	switch (reason) {
	case GSM_SUBSCRIBER_UPDATE_ATTACHED:
		/* Indicate "attached to LAC" */
		s->lac = bts->location_area_code;
		break;
	case GSM_SUBSCRIBER_UPDATE_DETACHED:
		/* Only detach if we are currently in this area */
		if (bts->location_area_code == s->lac)
			s->lac = 0;

		break;
	default:
		fprintf(stderr, "subscr_update with unknown reason: %d\n",
			reason);
		break;
	};
	return db_sync_subscriber(s);
}


