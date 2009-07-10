/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface 
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef _MNCC_H
#define _MNCC_H

#include <openbsc/linuxlist.h>

/* One end of a call */
struct gsm_call {
	struct llist_head entry;

	/* network handle */
	void *net;

	/* the 'local' transaction */
	u_int32_t callref;
	/* the 'remote' transaction */
	u_int32_t remote_ref;
};

#define MNCC_SETUP_REQ		0x0101
#define MNCC_SETUP_IND		0x0102
#define MNCC_SETUP_RSP		0x0103
#define MNCC_SETUP_CNF		0x0104
#define MNCC_SETUP_COMPL_REQ	0x0105
#define MNCC_SETUP_COMPL_IND	0x0106
/* MNCC_REJ_* is perfomed via MNCC_REL_* */
#define MNCC_CALL_CONF_IND	0x0107
#define MNCC_CALL_PROC_REQ	0x0108
#define MNCC_PROGRESS_REQ	0x0109
#define MNCC_ALERT_REQ		0x010a
#define MNCC_ALERT_IND		0x010b
#define MNCC_NOTIFY_REQ		0x010c
#define MNCC_NOTIFY_IND		0x010d
#define MNCC_DISC_REQ		0x010e
#define MNCC_DISC_IND		0x010f
#define MNCC_REL_REQ		0x0110
#define MNCC_REL_IND		0x0111
#define MNCC_REL_CNF		0x0112
#define MNCC_FACILITY_REQ	0x0113
#define MNCC_FACILITY_IND	0x0114
#define MNCC_START_DTMF_IND	0x0115
#define MNCC_START_DTMF_RSP	0x0116
#define MNCC_START_DTMF_REJ	0x0117
#define MNCC_STOP_DTMF_IND	0x0118
#define MNCC_STOP_DTMF_RSP	0x0119
#define MNCC_MODIFY_REQ		0x011a
#define MNCC_MODIFY_IND		0x011b
#define MNCC_MODIFY_RSP		0x011c
#define MNCC_MODIFY_CNF		0x011d
#define MNCC_MODIFY_REJ		0x011e
#define MNCC_HOLD_IND		0x011f
#define MNCC_HOLD_CNF		0x0120
#define MNCC_HOLD_REJ		0x0121
#define MNCC_RETRIEVE_IND	0x0122
#define MNCC_RETRIEVE_CNF	0x0123
#define MNCC_RETRIEVE_REJ	0x0124
#define MNCC_USERINFO_REQ	0x0125
#define MNCC_USERINFO_IND	0x0126
#define MNCC_REJ_REQ		0x0127
#define MNCC_REJ_IND		0x0128

#define MNCC_BRIDGE		0x0200
#define MNCC_FRAME_RECV		0x0201
#define MNCC_FRAME_DROP		0x0202
#define MNCC_LCHAN_MODIFY	0x0203

#define GSM_TRAU_FRAME		0x0300

#define GSM_MAX_FACILITY	128
#define GSM_MAX_SSVERSION	128
#define GSM_MAX_USERUSER	128

enum {
	_MNCC_E_BEARER_CAP,
	_MNCC_E_CALLED,
	_MNCC_E_CALLING,
	_MNCC_E_REDIRECTING,
	_MNCC_E_CONNECTED,
	_MNCC_E_CAUSE,
	_MNCC_E_USERUSER,
	_MNCC_E_PROGRESS,
	_MNCC_E_EMERGENCY,
	_MNCC_E_FACILITY,
	_MNCC_E_SSVERSION,
	_MNCC_E_CCCAP,
	_MNCC_E_KEYPAD,
	_MNCC_E_SIGNAL,
	_MNCC_E_LAST_ITEM,
};

#define	MNCC_F_BEARER_CAP	(1 << _MNCC_E_BEARER_CAP)
#define MNCC_F_CALLED		(1 << _MNCC_E_CALLED)
#define MNCC_F_CALLING		(1 << _MNCC_E_CALLING)
#define MNCC_F_REDIRECTING	(1 << _MNCC_E_REDIRECTING)
#define MNCC_F_CONNECTED	(1 << _MNCC_E_CONNECTED)
#define MNCC_F_CAUSE		(1 << _MNCC_E_CAUSE)
#define MNCC_F_USERUSER		(1 << _MNCC_E_USERUSER)
#define MNCC_F_PROGRESS		(1 << _MNCC_E_PROGRESS)
#define MNCC_F_EMERGENCY	(1 << _MNCC_E_EMERGENCY)
#define MNCC_F_FACILITY		(1 << _MNCC_E_FACILITY)
#define MNCC_F_SSVERSION	(1 << _MNCC_E_SSVERSION)
#define MNCC_F_CCCAP		(1 << _MNCC_E_CCCAP)
#define MNCC_F_KEYPAD		(1 << _MNCC_E_KEYPAD)
#define MNCC_F_SIGNAL		(1 << _MNCC_E_SIGNAL)

struct gsm_mncc_bearer_cap {
	int		transfer;
	int 		mode;
	int		coding;
	int		radio;
	int		speech_ctm;
	int		speech_ver[8];
};

struct gsm_mncc_number {
	int 		type;
	int 		plan;
	int		present;
	int		screen;
	char		number[33];
};

struct gsm_mncc_cause {
	int		location;
	int		coding;
	int		rec;
	int		rec_val;
	int		value;
	int		diag_len;
	char		diag[32];
};

struct gsm_mncc_useruser {
	int		proto;
	char		info[GSM_MAX_USERUSER + 1]; /* + termination char */
};

struct gsm_mncc_progress {
	int		coding;
	int		location;
	int 		descr;
};

struct gsm_mncc_facility {
	int		len;
	char		info[GSM_MAX_FACILITY];
};

struct gsm_mncc_ssversion {
	int		len;
	char		info[GSM_MAX_SSVERSION];
};

struct gsm_mncc_cccap {
	int		dtmf;
	int		pcp;
};


struct gsm_mncc {
	/* context based information */
	u_int32_t	msg_type;
	u_int32_t	callref;

	/* which fields are present */
	u_int32_t	fields;

	/* data derived informations (MNCC_F_ based) */
	struct gsm_mncc_bearer_cap	bearer_cap;
	struct gsm_mncc_number		called;
	struct gsm_mncc_number		calling;
	struct gsm_mncc_number		redirecting;
	struct gsm_mncc_number		connected;
	struct gsm_mncc_cause		cause;
	struct gsm_mncc_progress	progress;
	struct gsm_mncc_useruser	useruser;
	struct gsm_mncc_facility	facility;
	struct gsm_mncc_cccap		cccap;
	struct gsm_mncc_ssversion	ssversion;
	struct	{
		int		sup;
		int		inv;
	} clir;
	int		signal;

	/* data derived information, not MNCC_F based */
	int		keypad;
	int		more;
	int		notify; /* 0..127 */
	int		emergency;
	char		imsi[16];

	unsigned char	lchan_mode;
};

struct gsm_trau_frame {
	u_int32_t	msg_type;
	u_int32_t	callref;
	unsigned char	data[0];
};

char *get_mncc_name(int value);
int mncc_recv(struct gsm_network *net, int msg_type, void *arg);
void mncc_set_cause(struct gsm_mncc *data, int loc, int val);

#endif
