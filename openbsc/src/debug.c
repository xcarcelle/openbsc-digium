/* Debugging/Logging support code */
/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openbsc/debug.h>
#include <openbsc/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>

static unsigned int default_mask = 0xffffffff & ~(DMI|DMIB|DMEAS);

struct debug_info {
	const char *name;
	const char *color;
	const char *description;
	int number;
};

struct debug_context {
	struct gsm_lchan *lchan;
	struct gsm_subscriber *subscr;
	struct gsm_bts *bts;
};

static struct debug_context debug_context;
static void *tall_dbg_ctx = NULL;
static LLIST_HEAD(target_list);

#define DEBUG_CATEGORY(NUMBER, NAME, COLOR, DESCRIPTION) \
	{ .name = NAME, .color = COLOR, .description = DESCRIPTION, .number = NUMBER },

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

static const struct debug_info debug_info[] = {
	DEBUG_CATEGORY(DRLL,  "DRLL", "\033[1;31m", "")
	DEBUG_CATEGORY(DCC,   "DCC",  "\033[1;32m", "")
	DEBUG_CATEGORY(DMM,   "DMM",  "\033[1;33m", "")
	DEBUG_CATEGORY(DRR,   "DRR",  "\033[1;34m", "")
	DEBUG_CATEGORY(DRSL,  "DRSL", "\033[1;35m", "")
	DEBUG_CATEGORY(DNM,   "DNM",  "\033[1;36m", "")
	DEBUG_CATEGORY(DSMS,  "DSMS", "\033[1;37m", "")
	DEBUG_CATEGORY(DPAG,  "DPAG", "\033[1;38m", "")
	DEBUG_CATEGORY(DMNCC, "DMNCC","\033[1;39m", "")
	DEBUG_CATEGORY(DINP,  "DINP", "", "")
	DEBUG_CATEGORY(DMI,  "DMI", "", "")
	DEBUG_CATEGORY(DMIB,  "DMIB", "", "")
	DEBUG_CATEGORY(DMUX,  "DMUX", "", "")
	DEBUG_CATEGORY(DMEAS,  "DMEAS", "", "")
	DEBUG_CATEGORY(DSCCP, "DSCCP", "", "")
	DEBUG_CATEGORY(DMSC, "DMSC", "", "")
	DEBUG_CATEGORY(DMGCP, "DMGCP", "", "")
	DEBUG_CATEGORY(DHO, "DHO", "", "")
};

/*
 * Parse the category mask.
 * category1:category2:category3
 */
unsigned int debug_parse_category_mask(const char *_mask)
{
	unsigned int new_mask = 0;
	int i = 0;
	char *mask = strdup(_mask);
	char *category_token = NULL;

	category_token = strtok(mask, ":");
	do {
		for (i = 0; i < ARRAY_SIZE(debug_info); ++i) {
			if (strcasecmp(debug_info[i].name, category_token) == 0)
				new_mask |= debug_info[i].number;
		}
	} while ((category_token = strtok(NULL, ":")));


	free(mask);
	return new_mask;
}

static const char* color(int subsys)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(debug_info); ++i) {
		if (debug_info[i].number == subsys)
			return debug_info[i].color;
	}

	return "";
}

static void _output(struct debug_target *target, unsigned int subsys, char *file, int line,
		    int cont, const char *format, va_list ap)
{
	char col[30];
	char sub[30];
	char tim[30];
	char buf[4096];
	char final[4096];

	/* prepare the data */
	col[0] = '\0';
	sub[0] = '\0';
	tim[0] = '\0';
	buf[0] = '\0';

	/* are we using color */
	if (target->use_color)
		snprintf(col, sizeof(col), "%s", color(subsys));
	vsnprintf(buf, sizeof(buf), format, ap);

	if (!cont) {
		if (target->print_timestamp) {
			char *timestr;
			time_t tm;
			tm = time(NULL);
			timestr = ctime(&tm);
			timestr[strlen(timestr)-1] = '\0';
			snprintf(tim, sizeof(tim), "%s ", timestr);
		}
		snprintf(sub, sizeof(sub), "<%4.4x> %s:%d ", subsys, file, line);
	}

	snprintf(final, sizeof(final), "%s%s%s%s\033[0;m", col, tim, sub, buf);
	target->output(target, final);
}


static void _debugp(unsigned int subsys, int level, char *file, int line,
		    int cont, const char *format, va_list ap)
{
	struct debug_target *tar;

	llist_for_each_entry(tar, &target_list, entry) {
		int output = 0;

		/* subsystem is not supposed to be debugged */
		if (!(tar->debug_mask & subsys))
			continue;

		/*
		 * Apply filters here... if that becomes messy we will need to put
		 * filters in a list and each filter will say stop, continue, output
		 */
		if ((tar->filter_map & DEBUG_FILTER_ALL) != 0) {
			output = 1;
		} else if ((tar->filter_map & DEBUG_FILTER_IMSI) != 0
			      && debug_context.subscr && strcmp(debug_context.subscr->imsi, tar->imsi_filter) == 0) {
			output = 1;
		}

		if (output)
			_output(tar, subsys, file, line, cont, format, ap);
	}
}

void debugp(unsigned int subsys, char *file, int line, int cont, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	_debugp(subsys, LOGL_DEBUG, file, line, cont, format, ap);
	va_end(ap);
}

void debugp2(unsigned int subsys, unsigned int level, char *file, int line, int cont, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	_debugp(subsys, level, file, line, cont, format, ap);
	va_end(ap);
}

static char hexd_buff[4096];

char *hexdump(const unsigned char *buf, int len)
{
	int i;
	char *cur = hexd_buff;

	hexd_buff[0] = 0;
	for (i = 0; i < len; i++) {
		int len_remain = sizeof(hexd_buff) - (cur - hexd_buff);
		int rc = snprintf(cur, len_remain, "%02x ", buf[i]);
		if (rc <= 0)
			break;
		cur += rc;
	}
	hexd_buff[sizeof(hexd_buff)-1] = 0;
	return hexd_buff;
}



void debug_add_target(struct debug_target *target)
{
	llist_add_tail(&target->entry, &target_list);
}

void debug_del_target(struct debug_target *target)
{
	llist_del(&target->entry);
}

void debug_reset_context(void)
{
	memset(&debug_context, 0, sizeof(debug_context));
}

/* currently we are not reffing these */
void debug_set_context(int ctx, void *value)
{
	switch (ctx) {
	case BSC_CTX_LCHAN:
		debug_context.lchan = (struct gsm_lchan *) value;
		break;
	case BSC_CTX_SUBSCR:
		debug_context.subscr = (struct gsm_subscriber *) value;
		break;
	case BSC_CTX_BTS:
		debug_context.bts = (struct gsm_bts *) value;
		break;
	case BSC_CTX_SCCP:
		break;
	default:
		break;
	}
}

void debug_set_filter(struct debug_target *target, const char *filter_string)
{
}

void debug_set_imsi_filter(struct debug_target *target, const char *imsi)
{
	if (imsi) {
		target->filter_map |= DEBUG_FILTER_IMSI;
		target->imsi_filter = talloc_strdup(target, imsi); 
	} else if (target->imsi_filter) {
		target->filter_map &= ~DEBUG_FILTER_IMSI;
		talloc_free(target->imsi_filter);
		target->imsi_filter = NULL;
	}
}

void debug_set_all_filter(struct debug_target *target, int all)
{
	if (all)
		target->filter_map |= DEBUG_FILTER_ALL;
	else
		target->filter_map &= ~DEBUG_FILTER_ALL;
}

void debug_set_debug_mask(struct debug_target *target, unsigned int mask)
{
	target->debug_mask = mask;
}

void debug_set_use_color(struct debug_target *target, int use_color)
{
	target->use_color = use_color;
}

void debug_set_print_timestamp(struct debug_target *target, int print_timestamp)
{
	target->print_timestamp = print_timestamp;
}

static void _stderr_output(struct debug_target *target, const char *log)
{
	fprintf(target->tgt_stdout.out, "%s", log);
	fflush(target->tgt_stdout.out);
}

struct debug_target *debug_target_create(void)
{
	struct debug_target *target;

	target = talloc_zero(tall_dbg_ctx, struct debug_target);
	if (!target)
		return NULL;

	INIT_LLIST_HEAD(&target->entry);
	target->debug_mask = default_mask;
	target->use_color = 1;
	target->print_timestamp = 0;
	return target;
}

struct debug_target *debug_target_create_stderr(void)
{
	struct debug_target *target;

	target = debug_target_create();
	if (!target)
		return NULL;

	target->tgt_stdout.out = stderr;
	target->output = _stderr_output;
	return target;
}

void debug_init(void)
{
	tall_dbg_ctx = talloc_named_const(NULL, 1, "debug");
}
