/* Layer3 to Layer4 call handling */
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

#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/signal.h>

void free_trans(struct gsm_trans *trans);
static u_int32_t new_callref = 0x80000001;

static int mncc_handle_lchan_signal(unsigned int subsys, unsigned int signal,
				    void *handler_data, void *signal_data)
{
	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	struct gsm_lchan *lchan = (struct gsm_lchan *)handler_data;
	struct gsm_trans *trans, *temp;

	/* Free all transactions that are associated with the released lchan */
	llist_for_each_entry_safe(trans, temp, &lchan->ts->trx->bts->network->trans_list, entry) {
		if (trans->lchan == lchan)
			free_trans(trans);
	}


	return 0;
}

/*
 * This will be ran by the linker when loading the DSO. We use it to
 * do system initialization, e.g. registration of signal handlers.
 */
static __attribute__((constructor)) void on_dso_load_mncc(void)
{
	register_signal_handler(SS_LCHAN, mncc_handle_lchan_signal, NULL);
}

