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

#include <openbsc/gsm_data.h>
#include <openbsc/talloc.h>

void *tall_bsc_ctx;

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
	[GSM_PCHAN_UNKNOWN]	= "UNKNOWN",
};

const char *gsm_pchan_name(enum gsm_phys_chan_config c)
{
	if (c >= ARRAY_SIZE(pchan_names))
		return "INVALID";

	return pchan_names[c];
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
	struct gsm_bts_trx *trx = talloc(bts, struct gsm_bts_trx);
	int k;

	if (!trx)
		return NULL;

	memset(trx, 0, sizeof(*trx));
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

	llist_add(&trx->list, &bts->trx_list);

	return trx;
}

struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, enum gsm_bts_type type,
			      u_int8_t tsc, u_int8_t bsic)
{
	struct gsm_bts *bts = talloc(net, struct gsm_bts);

	if (!bts)
		return NULL;

	memset(bts, 0, sizeof(*bts));
	bts->network = net;
	bts->nr = net->num_bts++;
	bts->type = type;
	bts->tsc = tsc;
	bts->bsic = bsic;
	bts->num_trx = 0;
	INIT_LLIST_HEAD(&bts->trx_list);

	/* create our primary TRX */
	bts->c0 = gsm_bts_trx_alloc(bts);
	if (!bts->c0) {
		talloc_free(bts);
		return NULL;
	}
	bts->c0->ts[0].pchan = GSM_PCHAN_CCCH_SDCCH4;

	llist_add(&bts->list, &net->bts_list);

	return bts;
}

struct gsm_network *gsm_network_init(u_int16_t country_code, u_int16_t network_code,
				     int (*mncc_recv)(struct gsm_network *, int, void *),
				     gsm_layer3_cb *layer3_cb, void *layer3_data)
{
	struct gsm_network *net;

	net = talloc(tall_bsc_ctx, struct gsm_network);
	if (!net)
		return NULL;
	memset(net, 0, sizeof(*net));	

	net->country_code = country_code;
	net->network_code = network_code;
	net->num_bts = 0;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->bts_list);

	net->mncc_recv = mncc_recv;
	net->gsm_layer3 = layer3_cb;
	net->gsm_layer3_data = layer3_data;

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
		 ts->trx->bts->bts_nr, ts->trx->nr, ts->nr);

	return ts2str;
}

static const char *bts_types[] = {
	[GSM_BTS_TYPE_UNKNOWN] = "unknown",
	[GSM_BTS_TYPE_BS11] = "bs11",
	[GSM_BTS_TYPE_NANOBTS_900] = "nanobts900",
	[GSM_BTS_TYPE_NANOBTS_1800] = "nanobts1800",
};

enum gsm_bts_type parse_btstype(char *arg)
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

		if (bts->location_area_code == lac)
			return bts;
	}
	return NULL;
}

char *gsm_band_name(enum gsm_band band)
{
	switch (band) {
	case GSM_BAND_400:
		return "GSM 400";
	case GSM_BAND_850:
		return "GSM 850";
	case GSM_BAND_900:
		return "GSM 900";
	case GSM_BAND_1800:
		return "DCS 1800";
	case GSM_BAND_1900:
		return "PCS 1900";
	}
	return "invalid";
}

enum gsm_band gsm_band_parse(int mhz)
{
	switch (mhz) {
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

