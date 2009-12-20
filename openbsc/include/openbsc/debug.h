#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include "linuxlist.h"

#define DEBUG

#define DRLL		0x0001
#define DCC		0x0002
#define DMM		0x0004
#define DRR		0x0008
#define DRSL		0x0010
#define DNM		0x0020

#define DMNCC		0x0080
#define DSMS		0x0100
#define DPAG		0x0200
#define DMEAS		0x0400

#define DMI		0x1000
#define DMIB		0x2000
#define DMUX		0x4000
#define DINP		0x8000

#define DSCCP		0x10000
#define DMSC		0x20000

#define DMGCP		0x40000

#define DHO		0x80000

#ifdef DEBUG
#define DEBUGP(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, 0, fmt, ## args)
#define DEBUGPC(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, 1, fmt, ## args)
#else
#define DEBUGP(xss, fmt, args...)
#define DEBUGPC(ss, fmt, args...)
#endif


#define static_assert(exp, name) typedef int dummy##name [(exp) ? 1 : -1];

char *hexdump(const unsigned char *buf, int len);
void debugp(unsigned int subsys, char *file, int line, int cont, const char *format, ...) __attribute__ ((format (printf, 5, 6)));
void debug_parse_category_mask(const char* mask);
void debug_use_color(int use_color);
void debug_timestamp(int enable);

/* new logging interface */
#define LOGP(ss, level, fmt, args...) debugp2(ss, level, __FILE__, __LINE__, 0, fmt, ##args)
#define LOGPC(ss, level, fmt, args...) debugp2(ss, level, __FILE__, __LINE__, 1, fmt, ##args)

/* different levels */
#define LOGL_DEBUG	1	/* debugging information */
#define LOGL_INFO	3
#define LOGL_NOTICE	5	/* abnormal/unexpected condition */
#define LOGL_ERROR	7	/* error condition, requires user action */
#define LOGL_FATAL	8	/* fatal, program aborted */

/* context */
#define BSC_CTX_LCHAN	0
#define BSC_CTX_SUBSCR	1
#define BSC_CTX_BTS	2
#define BSC_CTX_SCCP	3

/* target */

enum {
	DEBUG_FILTER_IMSI = 1 << 0,
	DEBUG_FILTER_ALL = 1 << 1,
};

struct debug_target {
	char *filter;
	int filter_map;
	char *imsi_filter;


	/* TODO: some multidimensional field of values */
	int categories;

	union {
		struct {
                        FILE *out;
		} tgt_stdout;

		struct {
			int priority;
		} tgt_syslog;

		struct {
			void *vty;
		} tgt_vty;
	};

        void (*output) (struct debug_target *target, const char *string);

        struct llist_head entry;
};

/* use the above macros */
void debugp2(unsigned int subsys, unsigned int level, char *file, int line, int cont, const char *format, ...) __attribute__ ((format (printf, 6, 7)));
void debug_reset_context(void);
void debug_init(void);
void debug_add_target(struct debug_target *target);
void debug_del_target(struct debug_target *target);
void debug_set_context(int ctx, void *value);

/* unify the various filter methods into one string parsing... */
void debug_set_filter(struct debug_target *target, const char *filter_string);
void debug_set_imsi_filter(struct debug_target *target, const char *imsi);
void debug_set_all_filter(struct debug_target *target, int);


struct debug_target *debug_target_create(void);
struct debug_target *debug_target_create_stderr(void);
#endif /* _DEBUG_H */
