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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <openbsc/gsm_data.h>
#include <openbsc/talloc.h>
#include <openbsc/abis_nm.h>

void *tall_bsc_ctx;

const char *get_value_string(const struct value_string *vs, u_int32_t val)
{
	int i;

	for (i = 0;; i++) {
		if (vs[i].value == 0 && vs[i].str == NULL)
			break;
		if (vs[i].value == val)
			return vs[i].str;
	}
	return "unknown";
}

void set_ts_e1link(struct gsm_bts_trx_ts *ts, u_int8_t e1_nr,
		   u_int8_t e1_ts, u_int8_t e1_ts_ss)
{
	ts->e1_link.e1_nr = e1_nr;
	ts->e1_link.e1_ts = e1_ts;
	ts->e1_link.e1_ts_ss = e1_ts_ss;
}

static const char *pchan_names[] = {
	[GSM_PCHAN_NONE]	= "NONE",
	[GSM_PCHAN_CCCH]	= "CCCH",
	[GSM_PCHAN_CCCH_SDCCH4]	= "CCCH+SDCCH4",
	[GSM_PCHAN_TCH_F]	= "TCH/F",
	[GSM_PCHAN_TCH_H]	= "TCH/H",
	[GSM_PCHAN_SDCCH8_SACCH8C] = "SDCCH8",
	[GSM_PCHAN_PDCH]	= "PDCH",
	[GSM_PCHAN_TCH_F_PDCH]	= "TCH/F_PDCH",
	[GSM_PCHAN_UNKNOWN]	= "UNKNOWN",
};

const char *gsm_pchan_name(enum gsm_phys_chan_config c)
{
	if (c >= ARRAY_SIZE(pchan_names))
		return "INVALID";

	return pchan_names[c];
}

enum gsm_phys_chan_config gsm_pchan_parse(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pchan_names); i++) {
		if (!strcasecmp(name, pchan_names[i]))
			return i;
	}

	return -1;
}

static const char *lchan_names[] = {
	[GSM_LCHAN_NONE]	= "NONE",
	[GSM_LCHAN_SDCCH]	= "SDCCH",
	[GSM_LCHAN_TCH_F]	= "TCH/F",
	[GSM_LCHAN_TCH_H]	= "TCH/H",
	[GSM_LCHAN_UNKNOWN]	= "UNKNOWN",
};

const char *gsm_lchan_name(enum gsm_chan_t c)
{
	if (c >= ARRAY_SIZE(lchan_names))
		return "INVALID";

	return lchan_names[c];
}

static const char *chreq_names[] = {
	[GSM_CHREQ_REASON_EMERG]	= "EMERGENCY",
	[GSM_CHREQ_REASON_PAG]		= "PAGING",
	[GSM_CHREQ_REASON_CALL]		= "CALL",
	[GSM_CHREQ_REASON_LOCATION_UPD]	= "LOCATION_UPDATE",
	[GSM_CHREQ_REASON_OTHER]	= "OTHER",
};

const char *gsm_chreq_name(enum gsm_chreq_reason_t c)
{
	if (c >= ARRAY_SIZE(chreq_names))
		return "INVALID";

	return chreq_names[c];
}

struct gsm_bts_trx *gsm_bts_trx_alloc(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx = talloc_zero(bts, struct gsm_bts_trx);
	int k;

	if (!trx)
		return NULL;

	trx->bts = bts;
	trx->nr = bts->num_trx++;

	for (k = 0; k < TRX_NR_TS; k++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[k];
		int l;
		
		ts->trx = trx;
		ts->nr = k;
		ts->pchan = GSM_PCHAN_NONE;

		for (l = 0; l < TS_MAX_LCHAN; l++) {
			struct gsm_lchan *lchan;
			lchan = &ts->lchan[l];

			lchan->ts = ts;
			lchan->nr = l;
			lchan->type = GSM_LCHAN_NONE;
		}
	}

	llist_add_tail(&trx->list, &bts->trx_list);

	return trx;
}

struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, enum gsm_bts_type type,
			      u_int8_t tsc, u_int8_t bsic)
{
	struct gsm_bts *bts = talloc_zero(net, struct gsm_bts);
	int i;

	if (!bts)
		return NULL;

	bts->network = net;
	bts->nr = net->num_bts++;
	bts->type = type;
	bts->tsc = tsc;
	bts->bsic = bsic;
	bts->num_trx = 0;
	INIT_LLIST_HEAD(&bts->trx_list);
	bts->ms_max_power = 15;	/* dBm */

	for (i = 0; i < ARRAY_SIZE(bts->gprs.nsvc); i++) {
		bts->gprs.nsvc[i].bts = bts;
		bts->gprs.nsvc[i].id = i;
	}

	/* create our primary TRX */
	bts->c0 = gsm_bts_trx_alloc(bts);
	if (!bts->c0) {
		talloc_free(bts);
		return NULL;
	}
	bts->c0->ts[0].pchan = GSM_PCHAN_CCCH_SDCCH4;

	llist_add_tail(&bts->list, &net->bts_list);

	return bts;
}

struct gsm_network *gsm_network_init(u_int16_t country_code, u_int16_t network_code,
				     int (*mncc_recv)(struct gsm_network *, int, void *))
{
	struct gsm_network *net;

	net = talloc_zero(tall_bsc_ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->country_code = country_code;
	net->network_code = network_code;
	net->num_bts = 0;
	net->T3101 = GSM_T3101_DEFAULT;
	net->T3113 = GSM_T3113_DEFAULT;
	/* FIXME: initialize all other timers! */

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->bts_list);

	net->mncc_recv = mncc_recv;

	return net;
}

struct gsm_bts *gsm_bts_num(struct gsm_network *net, int num)
{
	struct gsm_bts *bts;

	if (num >= net->num_bts)
		return NULL;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (bts->nr == num)
			return bts;
	}

	return NULL;
}

struct gsm_bts_trx *gsm_bts_trx_num(struct gsm_bts *bts, int num)
{
	struct gsm_bts_trx *trx;

	if (num >= bts->num_trx)
		return NULL;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->nr == num)
			return trx;
	}

	return NULL;
}

static char ts2str[255];

char *gsm_ts_name(struct gsm_bts_trx_ts *ts)
{
	snprintf(ts2str, sizeof(ts2str), "(bts=%d,trx=%d,ts=%d)",
		 ts->trx->bts->nr, ts->trx->nr, ts->nr);

	return ts2str;
}

static const char *bts_types[] = {
	[GSM_BTS_TYPE_UNKNOWN] = "unknown",
	[GSM_BTS_TYPE_BS11] = "bs11",
	[GSM_BTS_TYPE_NANOBTS] = "nanobts",
};

enum gsm_bts_type parse_btstype(const char *arg)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(bts_types); i++) {
		if (!strcmp(arg, bts_types[i]))
			return i;
	}	
	return GSM_BTS_TYPE_BS11; /* Default: BS11 */
}

const char *btstype2str(enum gsm_bts_type type)
{
	if (type > ARRAY_SIZE(bts_types))
		return "undefined";
	return bts_types[type];
}

/* Search for a BTS in the given Location Area; optionally start searching
 * with start_bts (for continuing to search after the first result) */
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts)
{
	int i;
	struct gsm_bts *bts;
	int skip = 0;

	if (start_bts)
		skip = 1;

	for (i = 0; i < net->num_bts; i++) {
		bts = gsm_bts_num(net, i);

		if (skip) {
			if (start_bts == bts)
				skip = 0;
			continue;
		}

		if (lac == GSM_LAC_RESERVED_ALL_BTS || bts->location_area_code == lac)
			return bts;
	}
	return NULL;
}

char *gsm_band_name(enum gsm_band band)
{
	switch (band) {
	case GSM_BAND_400:
		return "GSM400";
	case GSM_BAND_850:
		return "GSM850";
	case GSM_BAND_900:
		return "GSM900";
	case GSM_BAND_1800:
		return "DCS1800";
	case GSM_BAND_1900:
		return "PCS1900";
	}
	return "invalid";
}

enum gsm_band gsm_band_parse(const char* mhz)
{
	while (*mhz && !isdigit(*mhz))
		mhz++;

	if (*mhz == '\0')
		return -EINVAL;

	switch (atoi(mhz)) {
	case 400:
		return GSM_BAND_400;
	case 850:
		return GSM_BAND_850;
	case 900:
		return GSM_BAND_900;
	case 1800:
		return GSM_BAND_1800;
	case 1900:
		return GSM_BAND_1900;
	default:
		return -EINVAL;
	}
}

static const char *gsm_auth_policy_names[] = {
	[GSM_AUTH_POLICY_CLOSED] = "closed",
	[GSM_AUTH_POLICY_ACCEPT_ALL] = "accept-all",
	[GSM_AUTH_POLICY_TOKEN] = "token",
};

enum gsm_auth_policy gsm_auth_policy_parse(const char *arg)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(gsm_auth_policy_names); i++) {
		if (!strcmp(arg, gsm_auth_policy_names[i]))
			return i;
	}
	return GSM_AUTH_POLICY_CLOSED;
}

const char *gsm_auth_policy_name(enum gsm_auth_policy policy)
{
	if (policy > ARRAY_SIZE(gsm_auth_policy_names))
		return "undefined";
	return gsm_auth_policy_names[policy];
}

