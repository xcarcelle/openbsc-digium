/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/db.h>
#include <openbsc/select.h>
#include <openbsc/debug.h>
#include <openbsc/e1_input.h>
#include <openbsc/talloc.h>
#include <openbsc/signal.h>

/* MCC and MNC for the Location Area Identifier */
static struct debug_target *stderr_target;
struct gsm_network *bsc_gsmnet = 0;
static const char *database_name = "hlr.sqlite3";
static const char *config_file = "openbsc.cfg";


/* timer to store statistics */
#define DB_SYNC_INTERVAL	60, 0
static struct timer_list db_sync_timer;

extern int bsc_bootstrap_network(int (*mmc_rev)(struct gsm_network *, int, void *),
				 const char *cfg_file);
extern int bsc_shutdown_net(struct gsm_network *net);

static void create_pcap_file(char *file)
{
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd = open(file, O_WRONLY|O_TRUNC|O_CREAT, mode);

	if (fd < 0) {
		perror("Failed to open file for pcap");
		return;
	}

	e1_set_pcap_fd(fd);
}

static void print_usage()
{
	printf("Usage: bsc_hack\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -l --database db-name The database to use\n");
	printf("  -p --pcap file  The filename of the pcap file\n");
	printf("  -T --timestamp Prefix every log line with a timestamp\n");
	printf("  -P --rtp-proxy Enable the RTP Proxy code inside OpenBSC\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"database", 1, 0, 'l'},
			{"authorize-everyone", 0, 0, 'a'},
			{"pcap", 1, 0, 'p'},
			{"timestamp", 0, 0, 'T'},
			{"rtp-proxy", 0, 0, 'P'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sl:ar:p:TPc:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			debug_set_use_color(stderr_target, 0);
			break;
		case 'd':
			debug_parse_category_mask(stderr_target, optarg);
			break;
		case 'l':
			database_name = strdup(optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'p':
			create_pcap_file(optarg);
			break;
		case 'T':
			debug_set_print_timestamp(stderr_target, 1);
			break;
		case 'P':
			ipacc_rtp_direct = 0;
			break;
		default:
			/* ignore */
			break;
		}
	}
}

extern void *tall_vty_ctx;
static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		bsc_shutdown_net(bsc_gsmnet);
		dispatch_signal(SS_GLOBAL, S_GLOBAL_SHUTDOWN, NULL);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

/* timer handling */
static int _db_store_counter(struct counter *counter, void *data)
{
	return db_store_counter(counter);
}

static void db_sync_timer_cb(void *data)
{
	/* store counters to database and re-schedule */
	counters_for_each(_db_store_counter, NULL);
	bsc_schedule_timer(&db_sync_timer, DB_SYNC_INTERVAL);
}

extern int bts_model_unknown_init(void);
extern int bts_model_bs11_init(void);
extern int bts_model_nanobts_init(void);

int main(int argc, char **argv)
{
	int rc;

	debug_init();
	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	talloc_ctx_init();
	on_dso_load_token();
	on_dso_load_rrlp();
	on_dso_load_ho_dec();
	stderr_target = debug_target_create_stderr();
	debug_add_target(stderr_target);

	bts_model_unknown_init();
	bts_model_bs11_init();
	bts_model_nanobts_init();

	/* enable filters */
	debug_set_all_filter(stderr_target, 1);

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	if (db_init(database_name)) {
		printf("DB: Failed to init database. Please check the option settings.\n");
		return -1;
	}
	printf("DB: Database initialized.\n");

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return -1;
	}
	printf("DB: Database prepared.\n");

	/* setup the timer */
	db_sync_timer.cb = db_sync_timer_cb;
	db_sync_timer.data = NULL;
	bsc_schedule_timer(&db_sync_timer, DB_SYNC_INTERVAL);

	rc = bsc_bootstrap_network(mncc_recv, config_file);
	if (rc < 0)
		exit(1);

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	while (1) {
		bsc_upqueue(bsc_gsmnet);
		debug_reset_context();
		bsc_select_main(0);
	}
}
