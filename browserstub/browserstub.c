/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Xunchao Hu, Heng Yin
 * @date Jan 24 2013
 */

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"

#include "utils/Output.h"
#include "utils.h"
#include "handlers.h"
#include "tracecap.h"
#include "cfi.h"

//basic stub for plugins
static plugin_interface_t browserstub_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle loadmodule_handle = DECAF_NULL_HANDLE;
static DECAF_Handle stub_create_script_handle = DECAF_NULL_HANDLE;
static DECAF_Handle stub_step_trace_handle = DECAF_NULL_HANDLE;
static DECAF_Handle allocate_heap_handle = DECAF_NULL_HANDLE;
static DECAF_Handle free_heap_handle = DECAF_NULL_HANDLE;
static DECAF_Handle realoc_handle = DECAF_NULL_HANDLE;



 char targetname[512];
 uint32_t targetpid = (uint32_t)-1;
 uint32_t targetcr3 = 0;

FILE * trace_log = NULL;
char *IN_BB_LOG = "./bblist.txt";
char *OUT_BB_LOG = "./";
static QEMUTimer *bb_recorder_timer = NULL;



 int memory_save(char *filename, uint32_t addr, uint32_t size,CPUState *env)
{
	 FILE *f;
    uint32_t l;
   
    uint8_t buf[1024];
    int ret = -1;

    f = fopen(filename, "wb");
    if (!f) {
        DECAF_printf("cannot open file %s\n", filename);
        return -1;
    }
    while (size != 0) {

    	memset(buf,0,sizeof(buf));

        l = sizeof(buf);
        if (l > size)
            l = size;
        cpu_memory_rw_debug(env, addr, buf, l, 0);
        
        if (fwrite(buf, 1, l, f) != l) {
            DECAF_printf("fwrite() error in do_memory_save\n");
            goto exit;
        }
        addr += l;
        size -= l;

    }

    ret = 0;

exit:
    fclose(f);
    return ret;


}

static void register_trace_hooks()
{

	stub_create_script_handle = hookapi_hook_function_byname(
			"stub.dll","create_script", 1, targetcr3,
			stub_create_script, NULL, 0);
	stub_step_trace_handle = hookapi_hook_function_byname(
			"stub.dll","send_response", 1, targetcr3,
			stub_step_trace, NULL, 0);

	/*allocate_heap_handle = hookapi_hook_function_byname(
			"kernel32.dll","LocalAlloc",1, targetcr3,
			LocalAlloc_handler, NULL, 0);
	free_heap_handle = hookapi_hook_function_byname(
			"kernel32.dll","LocalFree",1, targetcr3,
			LocalFree_handler, NULL, 0);

	realoc_handle = hookapi_hook_function_byname(
				"kernel32.dll","LocalReAlloc",1, targetcr3,
				LocalReAlloc_handler, NULL, 0);
	*/

	

}
static void unregister_hooks()
{
	hookapi_cleanup();

}



static void loadmainmodule_callback(VMI_Callback_Params* params)
{
    if(targetcr3 != 0) //if we have found the process, return immediately
    	return;
    DECAF_printf("new process created %s targetname  %s \n", params->cp.name, targetname);
	if (strcasecmp(targetname, params->cp.name) == 0) {
		targetpid = params->cp.pid;
		targetcr3 = params->cp.cr3;

		trace_log = fopen("./trace_log.txt","w");

//		register_insn_begin_cb(targetpid, "./trace_log.txt");

//		register_hooks();

//		register_heap_hooks();
// 		register_mem_cb();

		DECAF_printf("Process found: pid=%d, cr3=%08x\n", targetpid, targetcr3);
#if 1 // cfi plugin and script trace
		cfi_start_monitoring();

		register_trace_hooks();
#endif 
	}
}
#if 0
static void loadmodule_callback(VMI_Callback_Params* params)
{
	if(strcasecmp("stub.dll",params->lm.name) == 0)
	{
		//register_hooks();

	}
}
#endif


static void removeproc_callback(VMI_Callback_Params* params)
{
	//Stop the test when the monitored process terminates

	if(targetpid ==  params->rp.pid)
	{
		DECAF_printf("Monitored process (%s) has existed !\n", targetname);
		cfi_stop_monitoring();
	}

}

static void do_tracestop(Monitor* mon, const QDict* qdict)
{
	unregister_insn_begin_cb();
}
static void do_startmonitor(Monitor* mon, const QDict* qdict)
{
//	register_hooks();


}
static void do_browserstub(Monitor* mon, const QDict* qdict)
{
	DECAF_printf("targetname %s \n", targetname);
	if ((qdict != NULL) && (qdict_haskey(qdict, "procname"))) {
		strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
	}
	targetname[511] = '\0';
}

static void do_dumpcode(Monitor* mon, const QDict* qdict)
{
	char filename[512];
	FILE * f;
	if ((qdict != NULL) && (qdict_haskey(qdict, "filename"))) {
		strncpy(filename, qdict_get_str(qdict, "filename"), 512);
	}
	filename[511] = '\0';
	strcat(filename, ".code.txt");
	DECAF_printf("Dumping code  into %s\n", filename);
	f = fopen(filename,"w");
	if(f)
		dump_code(f);
	fclose(f);

}

static void do_dumpcodetrace(Monitor* mon, const QDict* qdict)
{
	char filename[512];
	FILE * f;
	if ((qdict != NULL) && (qdict_haskey(qdict, "filename"))) {
		strncpy(filename, qdict_get_str(qdict, "filename"), 512);
	}
	filename[511] = '\0';
	strcat(filename, ".trace.txt");
	DECAF_printf("Dumping code trace into %s\n", filename);
	f = fopen(filename,"w");
	if(f)
		dump_codetrace(f);
	fclose(f);

}
static void do_dumpall(Monitor * mon, const QDict* qdict)
{

	do_dumpcodetrace(mon, qdict);
	do_dumpcode(mon, qdict);


//finish here to dump all at on time

}
static void do_dumpstring(Monitor* mon, const QDict* qdict)
{
	char filename[512];
	FILE * f;
	if ((qdict != NULL) && (qdict_haskey(qdict, "filename"))) {
		strncpy(filename, qdict_get_str(qdict, "filename"), 512);
	}
	targetname[511] = '\0';
	DECAF_printf("Dumping heap information into %s \n", filename);
	f = fopen(filename, "w");
	if(f)
		dump_heap(f);

	fclose(f);
}

static void dump_basic_block(void *opaque)
{
	//DECAF_printf("dump basic block \n");
	int ret;
	uint32_t bb[2]; //[0] for eip, [1] for size of this block.
	char code[256];
	FILE * re = fopen(IN_BB_LOG, "r");
	if (re == NULL)
	{
	//	DECAF_printf("FILE %s not existed \n", IN_BB_LOG);
		goto end;
	}
	if (fread(bb, sizeof(uint32_t), 2, re) != EOF)
	{
		DECAF_printf("BB 0x%08x 0x%08x \n", bb[0], bb[1]);
		//read block info and dump code out.
		char out[100];
		sprintf(out, "%s%08x.bin",OUT_BB_LOG, bb[0]);
		FILE * out_code = fopen(out, "w");
		if(out_code == NULL)
		{
			DECAF_printf("%s is not created successfully\n",out);
			return;
		}
		if(bb[1] <256)
		{
			ret = DECAF_read_mem(cpu_single_env, bb[0], bb[1], code);
			if (ret == -1)
			{
				DECAF_printf("!!!!!! code swapped out \n");
			}
			else
			{
				fwrite(code,1, bb[1],out_code);
			}

		}
		else
		{
			//allocate a big buffer to store all the code.
			char * bbcode = malloc(bb[1]);

			ret = DECAF_read_mem(cpu_single_env, bb[0], bb[1], code);
			if (ret == -1)
			{
				DECAF_printf("!!!!!! code swapped out \n");
			}
			else
			{
				fwrite(code,1, bb[1],out_code);
			}
			free(bbcode);
		}
		fclose(out_code);

	}
	fclose(re);
end:
	qemu_mod_timer(bb_recorder_timer, qemu_get_clock_ms(rt_clock) + 1000);
}
void register_bb_recorder()
{
	clean_up_trace();
//	bb_recorder_timer = qemu_new_timer(rt_clock,SCALE_MS, dump_basic_block,NULL);
//	qemu_mod_timer(bb_recorder_timer, qemu_get_clock_ms(rt_clock) + 1000);
}
static int browserstub_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("Hello World\n");

	
	xed2_init();
	init_mem_record();
	//register for process create and process remove events
	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB,
			&loadmainmodule_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB,
			&removeproc_callback, NULL);

	//loadmodule_handle = VMI_register_callback(VMI_LOADMODULE_CB,
	//		&loadmodule_callback,NULL);

	if ((processbegin_handle == DECAF_NULL_HANDLE)
			|| (removeproc_handle == DECAF_NULL_HANDLE)
			|| (loadmodule_handle == DECAF_NULL_HANDLE)) {
		DECAF_printf(
				"Could not register for the create or remove proc events, or loadmodule events\n");
	}

	targetname[0] = '\0';
  	targetcr3 = 0;
  	targetpid = (uint32_t)(-1);


	return (0);
}

static void browserstub_cleanup(void)
{

	DECAF_printf("Bye world\n");

	if (processbegin_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_CREATEPROC_CB,
				processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}

	if (removeproc_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
		removeproc_handle = DECAF_NULL_HANDLE;
	}




	if(trace_log)
	{
		fclose(trace_log);
		trace_log = NULL;
	}
	clean_up_trace();
	unregister_block_begin();
	unregister_mem_cb();

	free_mem_record();


}

static mon_cmd_t browserstub_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin(void) {
	browserstub_interface.mon_cmds = browserstub_term_cmds;
	browserstub_interface.plugin_cleanup = &browserstub_cleanup;

	//initialize the plugin
	browserstub_init();
	return (&browserstub_interface);
}

