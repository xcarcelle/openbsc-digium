/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_utils.h>
#include <execinfo.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_decode(char *text, const u_int8_t *user_data, u_int8_t length)
{
	int i = 0;
	int l = 0;

        /* FIXME: We need to account for user data headers here */
	i += l;
	for (; i < length; i ++)
		*(text ++) =
			((user_data[(i * 7 + 7) >> 3] <<
			  (7 - ((i * 7 + 7) & 7))) |
			 (user_data[(i * 7) >> 3] >>
			  ((i * 7) & 7))) & 0x7f;
	*text = '\0';

	return i - l;
}


/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_encode(u_int8_t *result, const char *data)
{
	int i,j = 0;
	unsigned char ch1, ch2;
	int shift = 0;

	for ( i=0; i<strlen(data); i++ ) {

		ch1 = data[i] & 0x7F;
		ch1 = ch1 >> shift;
		ch2 = data[(i+1)] & 0x7F;
		ch2 = ch2 << (7-shift);

		ch1 = ch1 | ch2;

		result[j++] = ch1;

		shift++;

		if ((shift == 7) && (i+1<strlen(data))) {
			shift = 0;
			i++;
		}
	}

	return i;
}

/* determine power control level for given dBm value, as indicated
 * by the tables in chapter 4.1.1 of GSM TS 05.05 */
int ms_pwr_ctl_lvl(enum gsm_band band, unsigned int dbm)
{
	switch (band) {
	case GSM_BAND_400:
	case GSM_BAND_900:
	case GSM_BAND_850:
		if (dbm >= 39)
			return 0;
		else if (dbm < 5)
			return 19;
		else {
			/* we are guaranteed to have (5 <= dbm < 39) */
			return 2 + ((39 - dbm) / 2);
		}
		break;
	case GSM_BAND_1800:
		if (dbm >= 36)
			return 29;
		else if (dbm >= 34)	
			return 30;
		else if (dbm >= 32)
			return 31;
		else if (dbm == 31)
			return 0;
		else {
			/* we are guaranteed to have (0 <= dbm < 31) */
			return (30 - dbm) / 2;
		}
		break;
	case GSM_BAND_1900:
		if (dbm >= 33)
			return 30;
		else if (dbm >= 32)
			return 31;
		else if (dbm == 31)
			return 0;
		else {
			/* we are guaranteed to have (0 <= dbm < 31) */
			return (30 - dbm) / 2;
		}
		break;
	}
	return -EINVAL;
}

int ms_pwr_dbm(enum gsm_band band, u_int8_t lvl)
{
	lvl &= 0x1f;

	switch (band) {
	case GSM_BAND_400:
	case GSM_BAND_900:
	case GSM_BAND_850:
		if (lvl < 2)
			return 39;
		else if (lvl < 20)
			return 39 - ((lvl - 2) * 2) ;
		else
			return 5;
		break;
	case GSM_BAND_1800:
		if (lvl < 16)
			return 30 - (lvl * 2);
		else if (lvl < 29)
			return 0;
		else
			return 36 - ((lvl - 29) * 2);
		break;
	case GSM_BAND_1900:
		if (lvl < 16)
			return 30 - (lvl * 2);
		else if (lvl < 30)
			return -EINVAL;
		else
			return 33 - (lvl - 30);
		break;
	}
	return -EINVAL;
}

/* According to TS 08.05 Chapter 8.1.4 */
int rxlev2dbm(u_int8_t rxlev)
{
	if (rxlev > 63)
		rxlev = 63;

	return -110 + rxlev;
}

/* According to TS 08.05 Chapter 8.1.4 */
u_int8_t dbm2rxlev(int dbm)
{
	int rxlev = dbm + 110;

	if (rxlev > 63)
		rxlev = 63;
	else if (rxlev < 0)
		rxlev = 0;

	return rxlev;
}

void generate_backtrace()
{
	int i, nptrs;
	void *buffer[100];
	char **strings;

	nptrs = backtrace(buffer, ARRAY_SIZE(buffer));
	printf("backtrace() returned %d addresses\n", nptrs);

	strings = backtrace_symbols(buffer, nptrs);
	if (!strings)
		return;

	for (i = 1; i < nptrs; i++)
		printf("%s\n", strings[i]);

	free(strings);
}
