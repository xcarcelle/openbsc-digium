/* SMS based token authentication for ad-hoc GSM networks */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdio.h>
#include <openbsc/talloc.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/db.h>

#define TOKEN_SMS_TEXT "HAR 2009 GSM.  Register at http://har2009.gnumonks.org/ " \
			"Your IMSI is %s, auth token is %08X, phone no is %s."

extern struct gsm_sms *sms_from_text(struct gsm_subscriber *receiver,
				     const char *text);

static char *build_sms_string(struct gsm_subscriber *subscr, u_int32_t token)
{
	char *sms_str;
	unsigned int len;

	len = strlen(subscr->imsi) + 8 + strlen(TOKEN_SMS_TEXT);
	sms_str = talloc_size(tall_bsc_ctx, len);
	if (!sms_str)
		return NULL;

	snprintf(sms_str, len, TOKEN_SMS_TEXT, subscr->imsi, token,
		 subscr->extension);
	sms_str[len-1] = '\0';

	return sms_str;
}

static int token_subscr_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr = signal_data;
	struct gsm_sms *sms;
	int rc = 0;

	if (signal != S_SUBSCR_ATTACHED)
		return 0;

	if (subscr->net->auth_policy != GSM_AUTH_POLICY_TOKEN)
		return 0;

	if (subscr->flags & GSM_SUBSCRIBER_FIRST_CONTACT) {
		u_int32_t token;
		char *sms_str;

		/* we've seen this subscriber for the first time. */
		rc = db_subscriber_alloc_token(subscr, &token);
		if (rc != 0) {
			rc = -EIO;
			goto unauth;
		}

		sms_str = build_sms_string(subscr, token);
		if (!sms_str) {
			rc = -ENOMEM;
			goto unauth;
		}

		sms = sms_from_text(subscr, sms_str);
		talloc_free(sms_str);
		if (!sms) {
			rc = -ENOMEM;
			goto unauth;
		}

		rc = gsm411_send_sms_subscr(subscr, sms);

		/* FIXME: else, delete the subscirber from database */
unauth:

		/* make sure we don't allow him in again unless he clicks the web UI */
		subscr->authorized = 0;
		db_sync_subscriber(subscr);
		if (rc) {
			struct gsm_lchan *lchan = lchan_for_subscr(subscr);
			if (lchan) {
				u_int8_t auth_rand[16];
				/* kick the subscriber off the network */
				gsm48_tx_mm_auth_req(lchan, auth_rand, 0);
				gsm48_tx_mm_auth_rej(lchan);
				/* FIXME: close the channel early ?*/
				//gsm48_send_rr_Release(lchan);
			}
		}
	}

	return rc;
}

static int token_sms_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct gsm_sms *sms = signal_data;
	struct gsm_lchan *lchan;
	u_int8_t auth_rand[16];


	if (signal != S_SMS_DELIVERED)
		return 0;


	/* these are not the droids we've been looking for */
	if (!sms->receiver ||
	    !(sms->receiver->flags & GSM_SUBSCRIBER_FIRST_CONTACT))
		return 0;


	if (sms->receiver->net->auth_policy != GSM_AUTH_POLICY_TOKEN)
		return 0;


	lchan = lchan_for_subscr(sms->receiver);
	if (lchan) {
		/* kick the subscriber off the network */
		gsm48_tx_mm_auth_req(lchan, auth_rand, 0);
		gsm48_tx_mm_auth_rej(lchan);
		/* FIXME: close the channel early ?*/
		//gsm48_send_rr_Release(lchan);
	}

	return 0;
}

//static __attribute__((constructor)) void on_dso_load_token(void)
void on_dso_load_token(void)
{
	register_signal_handler(SS_SUBSCR, token_subscr_cb, NULL);
	register_signal_handler(SS_SMS, token_sms_cb, NULL);
}
