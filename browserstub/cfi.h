#ifndef _CFI_H_
#define _CFI_H_

#include <glib.h>
#include "DECAF_types.h"

#define MAX_THREADS 100
#define STACK_SIZE 512

struct Tid_Fid {
	uint32_t tid;
	uint32_t fiberId;
};

#define NAME_SIZE 1024
struct bin_file {
        char name[NAME_SIZE];
        gva_t image_base;
        unsigned int reloc_tbl_count;
        unsigned int exp_tbl_count;
        GHashTable *whitelist;
        gva_t *reloc_tbl;
        gva_t *exp_tbl;
};

#define MAX_MODULES		128

void do_monitor_proc(Monitor* mon, const QDict* qdict);
void do_set_print_stack(Monitor *mon, const QDict *qdict);
void do_set_guest_dir(Monitor *mon, const QDict *qdict);

 void cfi_start_monitoring();
 void cfi_stop_monitoring();
 int get_cur_call_stack(uint32_t ret[3]);

static int my_init(void);


#endif //_CFI_H_
