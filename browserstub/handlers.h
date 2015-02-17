/*
 * handlers.h
 *
 *  Created on: Feb 19, 2014
 *      Author: smarabbit
 */

#ifndef HANDLERS_H_
#define HANDLERS_H_

//int create_script(int message, int len1, char *script_file, int len2, char *compiled_script)
#ifdef __cplusplus
extern "C" {
#endif
#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"

#include "utils/Output.h"
#include "utils.h"
#include "tracecap.h"

#include "qemu-timer.h"
#include "browserstub.h"
#include "cfi.h"

void init_mem_record();
void free_mem_record();
void register_mem_cb();
void register_heap_hooks();
void unregister_insn_begin_cb();
void unregister_block_begin();
void unregister_mem_cb();

void mem_read_cb_handler(DECAF_Callback_Params *params);
void mem_write_cb_handler(DECAF_Callback_Params * params);

void block_begin_handler(DECAF_Callback_Params *params);
void insn_begin_cb(DECAF_Callback_Params* params);
void stub_create_script(void *opaque);
//int send_response(char *buffer,int len)
void stub_step_trace(void *opaque);

void LocalAlloc_handler(void *opaque);

void LocalFree_handler(void *opaque);

void LocalReAlloc_handler(void *opaque);

void malloc_handler(void *opaque);

void free_handler(void *opaque);

void realloc_handler(void *opaque);

void calloc_handler(void *opaque);
void new_op_handler(void *opaque);
void new_op_handler_ret(void *opaque);
void delete_op_handler(void *opaque);
void _MemRealloc_op_handler(void *opaque);
void dump_heap(FILE *log);
void dump_codetrace(FILE *log);
void dump_code(FILE *log);
void register_insn_begin_cb(int pid, const char * filename);
void clean_up_trace();
extern FILE *trace_log;
#ifdef __cplusplus
}
#endif


#endif /* HANDLERS_H_ */
