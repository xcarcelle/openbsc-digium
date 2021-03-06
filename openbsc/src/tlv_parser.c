#include <stdio.h>
#include <openbsc/tlv.h>
#include <openbsc/gsm_data.h>

struct tlv_definition tvlv_att_def;

int tlv_dump(struct tlv_parsed *dec)
{
	int i;

	for (i = 0; i <= 0xff; i++) {
		if (!dec->lv[i].val)
			continue;
		printf("T=%02x L=%d\n", i, dec->lv[i].len);
	}
	return 0;
}

/* o_tag:  output: tag found
 * o_len:  output: length of the data
 * o_val:  output: pointer to the data
 * def:     input: a structure defining the valid TLV tags / configurations
 * buf:     input: the input data buffer to be parsed
 * buf_len: input: the length of the input data buffer
 *
 * Also, returns the number of bytes consumed by the TLV entry
 */
int tlv_parse_one(u_int8_t *o_tag, u_int16_t *o_len, const u_int8_t **o_val,
		  const struct tlv_definition *def,
		  const u_int8_t *buf, int buf_len)
{
	u_int8_t tag;
	int len;

	tag = *buf;
	*o_tag = tag;

	/* FIXME: use tables for knwon IEI */
	switch (def->def[tag].type) {
	case TLV_TYPE_T:
		/* GSM TS 04.07 11.2.4: Type 1 TV or Type 2 T */
		*o_val = buf;
		*o_len = 0;
		len = 1;
		break;
	case TLV_TYPE_TV:
		*o_val = buf+1;
		*o_len = 1;
		len = 2;
		break;
	case TLV_TYPE_FIXED:
		*o_val = buf+1;
		*o_len = def->def[tag].fixed_len;
		len = def->def[tag].fixed_len + 1;
		break;
	case TLV_TYPE_TLV:
		/* GSM TS 04.07 11.2.4: Type 4 TLV */
		if (buf + 1 > buf + buf_len)
			return -1;
		*o_val = buf+2;
		*o_len = *(buf+1);
		len = *o_len + 2;
		if (len > buf_len)
			return -2;
		break;
	case TLV_TYPE_TvLV:
		if (*(buf+1) & 0x80) {
			/* like TLV, but without highest bit of len */
			if (buf + 1 > buf + buf_len)
				return -1;
			*o_val = buf+2;
			*o_len = *(buf+1) & 0x7f;
			len = *o_len + 2;
			if (len > buf_len)
				return -2;
			break;
		}
		/* like TL16V, fallthrough */
	case TLV_TYPE_TL16V:
		if (2 > buf_len)
			return -1;
		*o_val = buf+3;
		*o_len = *(buf+1) << 8 | *(buf+2);
		len = *o_len + 3;
		if (len > buf_len)
			return -2;
		break;
	default:
		return -3;
	}

	return len;
}

/* dec:    output: a caller-allocated pointer to a struct tlv_parsed,
 * def:     input: a structure defining the valid TLV tags / configurations
 * buf:     input: the input data buffer to be parsed
 * buf_len: input: the length of the input data buffer
 * lv_tag:  input: an initial LV tag at the start of the buffer
 * lv_tag2: input: a second initial LV tag following lv_tag 
 */
int tlv_parse(struct tlv_parsed *dec, const struct tlv_definition *def,
	      const u_int8_t *buf, int buf_len, u_int8_t lv_tag,
	      u_int8_t lv_tag2)
{
	int ofs = 0, num_parsed = 0;
	u_int16_t len;

	memset(dec, 0, sizeof(*dec));

	if (lv_tag) {
		if (ofs > buf_len)
			return -1;
		dec->lv[lv_tag].val = &buf[ofs+1];
		dec->lv[lv_tag].len = buf[ofs];
		len = dec->lv[lv_tag].len + 1;
		if (ofs + len > buf_len)
			return -2;
		num_parsed++;
		ofs += len;
	}
	if (lv_tag2) {
		if (ofs > buf_len)
			return -1;
		dec->lv[lv_tag2].val = &buf[ofs+1];
		dec->lv[lv_tag2].len = buf[ofs];
		len = dec->lv[lv_tag2].len + 1;
		if (ofs + len > buf_len)
			return -2;
		num_parsed++;
		ofs += len;
	}

	while (ofs < buf_len) {
		int rv;
		u_int8_t tag;
		const u_int8_t *val;

		rv = tlv_parse_one(&tag, &len, &val, def,
		                   &buf[ofs], buf_len-ofs);
		if (rv < 0)
			return rv;
		dec->lv[tag].val = val;
		dec->lv[tag].len = len;
		ofs += rv;
		num_parsed++;
	}
	//tlv_dump(dec);
	return num_parsed;
}

/* take a master (src) tlvdev and fill up all empty slots in 'dst' */
void tlv_def_patch(struct tlv_definition *dst, const struct tlv_definition *src)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dst->def); i++) {
		if (src->def[i].type == TLV_TYPE_NONE)
			continue;
		if (dst->def[i].type == TLV_TYPE_NONE)
			dst->def[i] = src->def[i];
	}
}

static __attribute__((constructor)) void on_dso_load_tlv(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(tvlv_att_def.def); i++)
		tvlv_att_def.def[i].type = TLV_TYPE_TvLV;
}
