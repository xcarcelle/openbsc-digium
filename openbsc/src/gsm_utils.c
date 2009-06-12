/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_utils.h>
#include <openbsc/gsm_04_08.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_decode(char *text, const u_int8_t *user_data, u_int8_t length)
{
	u_int8_t d_off = 0, b_off = 0;
	u_int8_t i;

	for (i=0;i<length;i++) {
		text[i] = ((user_data[d_off] + (user_data[d_off+1]<<8)) & (0x7f<<b_off))>>b_off;
		b_off += 7;
		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}
	text[i] = '\0';
	return 0;
}

/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_encode(u_int8_t *result, const char *data)
{
	int i;
	u_int8_t d_off = 0, b_off = 0;
	const int length = strlen(data);
	int out_length = (length * 8)/7;

	memset(result, 0, out_length);

	for (i = 0; i < length; ++i) {
		u_int8_t first  = (data[i] & 0x7f) << b_off;
		u_int8_t second = (data[i] & 0x7f) >> (8 - b_off);

		result[d_off] |= first;
		if (second != 0)
			result[d_off + 1] = second;

		b_off += 7;

		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}

	return out_length;
}

static char bcd2char(u_int8_t bcd)
{
	if (bcd < 0xa)
		return '0' + bcd;
	else
		return 'A' + (bcd - 0xa);
}

/* Convert Mobile Identity (GSM 04.08 10.5.1.4) to string */
int gsm_mi_to_string(char *string, int str_len, u_int8_t *mi, int mi_len)
{
	int i;
	u_int8_t mi_type;
	char *str_cur = string;
	u_int32_t tmsi;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_NONE:
		break;
	case GSM_MI_TYPE_TMSI:
		/* Table 10.5.4.3, reverse generate_mid_from_tmsi */
		if (mi_len == GSM_TMSI_LEN && mi[0] == (0xf0 | GSM_MI_TYPE_TMSI)) {
			memcpy(&tmsi, &mi[1], 4);
			tmsi = ntohl(tmsi);
			return snprintf(string, str_len, "%u", tmsi);
		}
		break;
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		*str_cur++ = bcd2char(mi[0] >> 4);

                for (i = 1; i < mi_len; i++) {
			if (str_cur + 2 >= string + str_len)
				return str_cur - string;
			*str_cur++ = bcd2char(mi[i] & 0xf);
			/* skip last nibble in last input byte when GSM_EVEN */
			if( (i != mi_len-1) || (mi[0] & GSM_MI_ODD))
				*str_cur++ = bcd2char(mi[i] >> 4);
		}
		break;
	default:
		break;
	}
	*str_cur++ = '\0';

	return str_cur - string;
}

