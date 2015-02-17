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

/*
 * handlers.c
 *
 *  Created on: Feb 19, 2014
 *      Author: Xunchao Hu
 */

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "DECAF_target.h"
#include "utils/Output.h"
#include "utils.h"

 #include "vmi_c_wrapper.h" // AWH

#include "handlers.h"

#include <list>
#include <map>
#include <string>
#include <sstream>
typedef struct {
	gva_t addr;
	uint32_t len;
	uint32_t status; //1 for live, 0 for freeed.
} Heap_Info;



typedef struct{
	gva_t vaddr;
	uint32_t value;
	uint32_t size;
	uint32_t type; //1 for mem_read 2 for mem_write 3 for block record
	uint32_t cur_eip;
	uint32_t call_stack[2];
} Mem_Record;
#define MAX_MEM_RECOCRD_LEN 104857600 //2147483648//1024*1024*1024*2
Mem_Record *mem_record_list;//[MAX_MEM_RECOCRD_LEN];
uint32_t MEM_RECORD_INDEX = 0;

std::list<Heap_Info *> heap_list;
std::map<gva_t, Heap_Info *> heap_map;
gva_t heap_start = 0;
gva_t heap_end = 0;
std::map<std::string,std::string> source_map;
std::string code_trace;
uint32_t EVAL_CODE_ID = 0;
std::string current_step_trace;
std::string mem_read_write_log;
DECAF_Handle insn_begin_handle = DECAF_NULL_HANDLE;
DECAF_Handle malloc_handle = DECAF_NULL_HANDLE;
DECAF_Handle free_handle = DECAF_NULL_HANDLE;
DECAF_Handle realloc_handle = DECAF_NULL_HANDLE;
DECAF_Handle calloc_handle = DECAF_NULL_HANDLE;
DECAF_Handle mem_read_cb_handle = DECAF_NULL_HANDLE;
DECAF_Handle mem_write_cb_handle = DECAF_NULL_HANDLE;
DECAF_Handle new_op_cb_handle = DECAF_NULL_HANDLE;
DECAF_Handle delete_op_cb_handle = DECAF_NULL_HANDLE;
DECAF_Handle block_begin_cb_handle = DECAF_NULL_HANDLE;
DECAF_Handle block_end_cb_handle = DECAF_NULL_HANDLE;

FILE * bin_trace_log = NULL;
uint32_t js_trace_count = 0;

void init_mem_record()
{
	mem_record_list = (Mem_Record*) malloc(sizeof(Mem_Record)*1024*1024*1024);
}
void free_mem_record()
{
	free(mem_record_list);
}

void register_mem_cb()
{

	if(mem_read_cb_handle |mem_write_cb_handle)
		return;
	should_monitor = 1;
	mem_read_cb_handle = DECAF_register_callback(DECAF_MEM_READ_CB,
		mem_read_cb_handler , &should_monitor);
	mem_write_cb_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,
		mem_write_cb_handler, &should_monitor);
}
void unregister_mem_cb()
{
	if(mem_read_cb_handle)
		DECAF_unregister_callback(DECAF_MEM_READ_CB, mem_read_cb_handle);
	if(mem_write_cb_handle)
		DECAF_unregister_callback(DECAF_MEM_WRITE_CB, mem_write_cb_handle);
	mem_write_cb_handle = DECAF_NULL_HANDLE;
	mem_read_cb_handle = DECAF_NULL_HANDLE;
}
void register_block_begin()
{
	if(block_begin_cb_handle)
		return;
	should_monitor = 1;
	block_begin_cb_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB,
		block_begin_handler, &should_monitor);
}
void unregister_block_begin()
{
	if( block_begin_cb_handle )
		DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb_handle);
	block_begin_cb_handle = DECAF_NULL_HANDLE;
}

void register_insn_begin_cb(int pid, const char * filename)
{
	DECAF_printf(" PID %d\n", pid);

	if(pid != -1)
	{
		tracing_start(pid, filename);
   		insn_begin_handle =  DECAF_register_callback(DECAF_INSN_BEGIN_CB,
			insn_begin_cb, &should_monitor);

	}

}
void unregister_insn_begin_cb()
{
	if(insn_begin_handle)
	{
		DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, insn_begin_handle);
		insn_begin_handle = DECAF_NULL_HANDLE;
	}
	tracing_stop();


}
void register_new_op_hooks()
{
	if(new_op_cb_handle)
		return;
/*
	hookapi_hook_function(
               int is_global,
               target_ulong pc,
               target_ulong cr3,
               hook_proc_t fnhook, 
               void *opaque, 
               uint32_t sizeof_opaque
               );
*/
// 0x75C51038 : new operator in jscript.dll ie6

//0x77C29CC5: new operator in msvcrt.dll
	if(targetpid == 0)
	{
		DECAF_printf("Registeration of new_op hook failed,please specify target process \n");
		return;
	}
	DECAF_printf("Hooking new operator \n");

	uint32_t targetcr3 = VMI_find_cr3_by_pid_c(targetpid);

	new_op_cb_handle = hookapi_hook_function(1, 0x77C29CC5, targetcr3,new_op_handler, NULL, 0);
	// 0x7DC9AAB3: _MemAlloc(x) mshtml.dll

 hookapi_hook_function(1, 0x7DC9AAB3, targetcr3,new_op_handler, NULL, 0);
	// 0x7DC9AA6E: _MemRealloc
	// hookapi_hook_function(1, 0x7DC9AA6E, targetcr3,_MemRealloc_op_handler, NULL, 0);


}

void register_delete_op_hooks()
{
	//0x77C29CDD: delete operator in msvcrt.dll
	if(delete_op_cb_handle)
		return;

	if(targetpid == 0)
	{
		DECAF_printf("Registeration of delete_op hook failed,please specify target process \n");
		return;
	}
	DECAF_printf("Hooking delete operator \n");

	uint32_t targetcr3 = VMI_find_cr3_by_pid_c(targetpid);

	delete_op_cb_handle = hookapi_hook_function(1, 0x77C29CDD, targetcr3,delete_op_handler, NULL, 0);

	//0x7DC99430: _MemFree
   hookapi_hook_function(1, 0x7DC99430, targetcr3,delete_op_handler, NULL, 0);

}

void register_heap_hooks()
{
	if(malloc_handle | free_handle | realloc_handle | calloc_handle)
		return;
	uint32_t targetcr3 = VMI_find_cr3_by_pid_c(targetpid);
	malloc_handle = hookapi_hook_function_byname(
			"msvcr100.dll","malloc",1, targetcr3,
			malloc_handler, NULL, 0);
	free_handle = hookapi_hook_function_byname(
			"msvcr100.dll","free",1, targetcr3,
			free_handler, NULL, 0);

	realloc_handle = hookapi_hook_function_byname(
				"msvcr100.dll","realloc",1, targetcr3,
				realloc_handler, NULL, 0);
	calloc_handle = hookapi_hook_function_byname(
				"msvcr100.dll", "calloc", 1, targetcr3,
				calloc_handler, NULL, 0);
}
void unregister_heap_hooks()
{
	hookapi_remove_hook(malloc_handle);
	hookapi_remove_hook(free_handle);
	hookapi_remove_hook(realloc_handle);
	hookapi_remove_hook(calloc_handle);
	malloc_handle = DECAF_NULL_HANDLE;
	free_handle = DECAF_NULL_HANDLE;
	realloc_handle = DECAF_NULL_HANDLE;
	calloc_handle = DECAF_NULL_HANDLE;

}
void block_begin_handler(DECAF_Callback_Params *params)
{
	//uint32_t ret[3];// for callstack info
	if(cpu_single_env->cr[3] != targetcr3)
		return;
	if(DECAF_is_in_kernel(cpu_single_env))
		return;
	//if(get_cur_call_stack(ret) == -1)
	
	//	return;

	Mem_Record * mr = &mem_record_list[MEM_RECORD_INDEX];
	mr->vaddr = 0;
	mr->value = 0;
	mr->size = params->bb.tb->size;
	mr->type = 3;//for block record
	mr->cur_eip = params->bb.tb->pc -params->bb.tb->cs_base;
	mr->call_stack[0] = 0;
	mr->call_stack[1] = 0;

	MEM_RECORD_INDEX++;

	//DECAF_printf("0x%08x 0x%08x 0x%08x \n", cpu_single_env->eip, mr->cur_eip, mr->size);

	if(MEM_RECORD_INDEX >= MAX_MEM_RECOCRD_LEN)
	{
		fwrite(mem_record_list,sizeof(Mem_Record), MAX_MEM_RECOCRD_LEN, bin_trace_log);
		MEM_RECORD_INDEX = 0;

	}

}

void mem_read_cb_handler(DECAF_Callback_Params *params)
{
#if 0
	gva_t vaddr = params->mr.vaddr;
	/* for old heap list check.
	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {
		Heap_Info * hi = (Heap_Info *) *it;
		if( (vaddr >= hi->addr) & (vaddr <= hi->addr+hi->len) & (hi->status == 0))
		{
			DECAF_printf("read freed heap  %s\n", current_step_trace.c_str());
		}
	}
	*/

   if( (vaddr < heap_start) | (vaddr > heap_end))
   	return;
   int isFreed = 0;
   for(std::map<gva_t, Heap_Info*>::iterator it = heap_map.begin(); it != heap_map.end(); ++it)
   {
   		Heap_Info * hi = it->second;

   		if( vaddr < hi->addr)
   			continue;
   		if( vaddr > (hi->addr + hi->len))
   			continue;

   		if( hi->status == 0)
		{
			isFreed = 1;
		//	break;
		}
		else
		{
			isFreed = 0;
		//	break;
		}
   }
   if( isFreed == 1 )
   		DECAF_printf("read freed heap  %s\n", current_step_trace.c_str());
#endif

  //  gva_t vaddr ;
//	gva_t size ;
//	gva_t paddr ;
   	uint32_t ret[3];// for callstack info
	if(cpu_single_env->cr[3] != targetcr3)
		return;
	if(DECAF_is_in_kernel(cpu_single_env))
		return;
	if(get_cur_call_stack(ret) == -1)
		return;


	Mem_Record * mrs = &mem_record_list[MEM_RECORD_INDEX];
	mrs->vaddr = params->mr.vaddr;
	DECAF_read_mem(cpu_single_env, params->mr.vaddr, params->mr.dt, &(mrs->value));
	mrs->size = params->mr.dt;
	mrs->type = 1;
	

	mrs->cur_eip = ret[0];
	mrs->call_stack[0] = ret[1];
	mrs->call_stack[1] = ret[2];

	MEM_RECORD_INDEX++;

	if(MEM_RECORD_INDEX >= MAX_MEM_RECOCRD_LEN)
	{
		fwrite(mem_record_list,sizeof(Mem_Record), MAX_MEM_RECOCRD_LEN, bin_trace_log);
		MEM_RECORD_INDEX = 0;

	}

	


	//DECAF_printf("%s", mem_read_write_log.c_str());
	//fprintf(trace_log, "READ 0x%08x 0x%08x %d\n", vaddr, paddr, size);
	//fflush(trace_log);

}

void mem_write_cb_handler(DECAF_Callback_Params * params)
{
#if 0
	gva_t vaddr = params->mw.vaddr;
	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {
		Heap_Info * hi = (Heap_Info *) *it;
		if((vaddr >= hi->addr )& (vaddr <= hi->addr+hi->len) & (hi->status == 0))
		{
			DECAF_printf("write to freed heap  %s\n", current_step_trace.c_str());
		}
	}
#endif
	uint32_t ret[3];
	//test for shellcode identification
	if(cpu_single_env->cr[3] != targetcr3)
		return;
	if(DECAF_is_in_kernel(cpu_single_env))
		return;
	if(get_cur_call_stack(ret) == -1 )
		return;


	Mem_Record * mrs = & mem_record_list[MEM_RECORD_INDEX];
	mrs->vaddr = params->mw.vaddr;
	mrs->value = params->mw.paddr; //use paddr to store value for now
	mrs->size = params->mw.dt;
	mrs->type = 2;
	

	mrs->cur_eip = ret[0];
	mrs->call_stack[0] = ret[1];
	mrs->call_stack[1] = ret[2];

	MEM_RECORD_INDEX++;

	if(MEM_RECORD_INDEX >= MAX_MEM_RECOCRD_LEN)
	{
		fwrite(mem_record_list,sizeof(Mem_Record), MAX_MEM_RECOCRD_LEN, bin_trace_log);
		MEM_RECORD_INDEX = 0;

	}


	//DECAF_printf("WRITE 0x%08x 0x%08x %d\n", vaddr, paddr, size);

	//fprintf(trace_log, "WRITE 0x%08x 0x%08x %d\n", vaddr, paddr, size);
	//fflush(trace_log);


}

void insn_begin_cb(DECAF_Callback_Params* params)
{

	CPUState* env = NULL;
	if (!params) return;
	
	env = params->ib.env;

	if (DECAF_is_in_kernel(env))
		return;


	if(DECAF_getPGD(env) != tracecr3)
		return;


	cpu_disable_ticks();

	decode_address(env->eip, &eh);
	write_insn(tracelog,&eh);

	cpu_enable_ticks();

}
void write_heap_to_file(FILE * log, gva_t addr, uint32_t len)
{
	char *buf;

	buf = (char*) malloc(len/2+1);

	readwstr_with_len(addr , buf, len);

	buf[len/2] = '\0';
	fprintf(log,"%s END%d\n", buf, len);

//	fwrite(buf, sizeof(char), len/2+1, log);
	free(buf);


}

void dump_heap(FILE * log)
{
	DECAF_printf("dump heap: SIZE %d\n", heap_list.size());

	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {
		Heap_Info * hi = (Heap_Info *) *it;
		write_heap_to_file(log, hi->addr, hi->len);
	}

}
void dump_codetrace(FILE *log)
{
	if(!log)
		return ;
	fprintf(log, "%s \n", code_trace.c_str());
}

void dump_code(FILE *log)
{
	std::map<std::string,std::string>::iterator it = source_map.begin();

	for(;it!=source_map.end(); ++it)
	{
		fprintf(log, "FILE %s\n%s\n",it->first.c_str() , it->second.c_str());

	}
}

void write_and_create_bintrace(const char * filename)
{
	if(bin_trace_log)
	{
		fwrite(mem_record_list,sizeof(Mem_Record), MEM_RECORD_INDEX, bin_trace_log);
		MEM_RECORD_INDEX = 0;
		fclose(bin_trace_log);
	}
	bin_trace_log = fopen(filename, "w");
}

//int create_script(int message, int len1, char *script_file, int len2, char *compiled_script)

 void stub_create_script(void *opaque)
{
	char *script_file, *script_source;
	uint32_t stack[6];

	DECAF_read_mem(cpu_single_env, cpu_single_env->regs[R_ESP], 4*6, (void*)stack);
	script_file = (char *) g_malloc(2*stack[2]+1);
	readwstr( stack[3], script_file); //read script_file
    printf("%s \n", script_file);

    script_source = (char *) g_malloc(2*stack[4]+1);
    readwstr( stack[5], script_source);
    printf("%s \n", script_source);

    g_free(script_file);
    g_free(script_source);



}
 /*
  *
  * struct StackFrame {
  *
  * 	TCHAR* fileName;
  * 	ULONG line;
  * 	ULONG col;
  * 	ULONG position;
  * 	ULONG size;
  * 	TCHAR *location;
  * 	TCHAR *type;
  * 	TCHAR* code;
  * 	ULONG codesize;
  *
  *
  */

 std::string getString( uint32_t number)
 {
 	std::ostringstream convert;
 	convert << number;
 	return convert.str();
 }
 void read_stack_frame(void * stack, uint32_t len)
 {
	 char *source;
	 char filename[MAX_NAME_LENGTH];
	 gva_t * StackFrame = (gva_t *) stack;

	 //read filename
	 readwstr( StackFrame[0], filename);
	 std::string filename_s(filename);
	 if( StackFrame[7]!=0) //means new code
	 {

		 //read code
		 source = (char *) malloc(StackFrame[8]+1);
		 readwstr_with_len( StackFrame[7],source, StackFrame[8]*2);
		 std::string source_s(source);

		 //insert into source_map
		 DECAF_printf("new source code from %s %d\n", filename, StackFrame[8]);
		 if(filename_s.compare("eval code") ==0)
			sprintf(filename, "evalcode%d", EVAL_CODE_ID++);
		 filename_s = std::string(filename);

		 source_map[filename_s] = source_s;

	 }
	 if(filename_s.compare("eval code") ==0)
	 {
	 	sprintf(filename, "evalcode%d",  EVAL_CODE_ID-1);
	 	filename_s = std::string(filename);
	 }
	 //read step trace
	 std::string filesource = source_map[filename_s];

	 //DECAF_printf("%d %d %d\n", filesource.size(), StackFrame[3]+StackFrame[4], filesource.size() - StackFrame[3]);
	 if(filesource.size() < StackFrame[3])
	 {
	 	DECAF_printf("out of source bound \n");
	 	return;
	 }

	std::string step_trace;// = filesource.substr( StackFrame[3], StackFrame[4]);
	std::string offset ;//= getString(StackFrame[3]);
	std::string len_t;
	 if(filesource.size() > StackFrame[4]+StackFrame[3])
	 {

		step_trace = filesource.substr( StackFrame[3], StackFrame[4]);
		offset = getString(StackFrame[3]);
		len_t = getString(StackFrame[4]);
		//DECAF_printf("%s \n", step_trace.c_str());
		//if(trace_log)
		//fprintf(trace_log, "%s \n", step_trace.c_str());
		code_trace += offset+" "+len_t+" "+filename_s+" "+step_trace + "\n";
	 }
	 else
	 {
	 	step_trace = filesource.substr( StackFrame[3], filesource.size()-StackFrame[3]);
	 	offset = getString(StackFrame[3]);
		len_t = getString(StackFrame[4]);
		//DECAF_printf("%s \n", step_trace.c_str());
		//if(trace_log)
		//fprintf(trace_log, "%s \n", step_trace.c_str());
		code_trace += offset+" "+len_t+" "+filename_s+" "+step_trace + "\n";
	 }


/*

	 if(new_op_cb_handle)
	 {

	 }
	 else
	 {
	 	register_new_op_hooks();
	 }

	 if(delete_op_cb_handle)
	 {

	 }
	 else
	 {
	 	register_delete_op_hooks();
	 }

*/

 	std::string step_trace_name = offset + "A"+ len_t +".bin";
 	std::string count = std::to_string(js_trace_count++) +".mem";
 	current_step_trace = count +" "+step_trace+" "+ step_trace_name;

 	 if(mem_write_cb_handle)
	 {
	 	fprintf(trace_log, "%s\n", current_step_trace.c_str());
	 	fflush(trace_log);
	 	write_and_create_bintrace(count.c_str());
	 }
	 else
	 {
	 	time_t rawtime;
	 	time(&rawtime);
	 	DECAF_printf("current time %s", ctime(&rawtime));
	 	register_mem_cb();
	 	fprintf(trace_log, "%s\n", current_step_trace.c_str());
	 	fflush(trace_log);
	 	write_and_create_bintrace(count.c_str());
	 }

	 if(!block_begin_cb_handle)
	 	register_block_begin();


	 //record execution trace
#if 0
	 std::string new_trace_name = count + ".bin";
	 if(insn_begin_handle)
	 {
	 	unregister_insn_begin_cb();
	 	register_insn_begin_cb(targetpid, new_trace_name.c_str());
	 	//DECAF_printf("monitor: %s\n", code_trace.c_str());
	 }
	 else
	 {
	 	register_insn_begin_cb(targetpid, new_trace_name.c_str());
	 	//DECAF_printf("monitor: %s\n", code_trace.c_str());
	 }
#endif
 //	register_heap_hooks();
 //	register_mem_cb();

 //	unregister_heap_hooks();




 }
//int send_response(char *buffer,int len)
 void stub_step_trace(void *opaque)
{
	char *StackFrame;
	uint32 stack[3];
	DECAF_read_mem(cpu_single_env, cpu_single_env->regs[R_ESP], 4*3, (void*)stack);

	//DECAF_printf("stackframe size %d\n", stack[2]);

	StackFrame = (char *) malloc(stack[2]);
	DECAF_read_mem(cpu_single_env, stack[1], stack[2], (void*) StackFrame);

	if( StackFrame[0] =='h' && StackFrame[2] =='t')// new url object
	{
		return;
	}

	read_stack_frame(StackFrame, stack[2]);
	//fprintf(trace_log,"%s \n",buf);


}
/*
 *

HLOCAL WINAPI LocalAlloc(
  _In_  UINT uFlags,
  _In_  SIZE_T uBytes
);

 */

 typedef struct  {
	 uint32_t len;
	 DECAF_Handle hook_handle;

 } LocalAlloc_ctx, alloc_ctx,new_ctx;

typedef struct  {
	 uint32_t len;
	 uint32_t addr;
	 DECAF_Handle hook_handle;

 } realloc_ctx;

 void LocalAlloc_handler_ret(void *opaque)
 {
	 uint32_t len;
	 target_ulong heap_addr;
	 LocalAlloc_ctx *ctx = (LocalAlloc_ctx*)opaque;
	 len = ctx->len;
	 heap_addr = cpu_single_env->regs[R_EAX];

	 if( len< 8) //if heap size is too small, ignore it
		 return;
	 Heap_Info * hi = (Heap_Info *) malloc(sizeof(Heap_Info));
	 hi->addr = heap_addr;
	 hi->len  = len;
	 heap_list.push_back(hi);



	 hookapi_remove_hook(ctx->hook_handle);

	 free(ctx);

 }

 void LocalAlloc_handler(void *opaque)
 {
	 gva_t stack[3];
	 LocalAlloc_ctx * lctx =(LocalAlloc_ctx*) g_malloc(sizeof(LocalAlloc_ctx));

	 DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*3, stack);
	 lctx->len = stack[2];
	 lctx->hook_handle = hookapi_hook_return(stack[0],LocalAlloc_handler_ret, lctx, sizeof(*lctx));
  //   DECAF_printf("0x%08x 0x%08x 0x%08x\n",stack[0],stack[1],stack[2]);

 }

/*
 * HLOCAL WINAPI LocalFree(
  _In_  HLOCAL hMem
);
 *
 */
void LocalFree_handler(void *opaque) {
	gva_t stack[2];

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 2, stack);

	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {
		Heap_Info * hi = (Heap_Info *) *it;

		if (hi->addr == stack[1]) {
			write_heap_to_file(trace_log, hi->addr, hi->len);
			heap_list.erase(it);
			free(hi);
			break;
		}
	}
//	DECAF_printf(" size %d \n", heap_list.size());

}
/*
 * HLOCAL WINAPI LocalReAlloc(
 _In_  HLOCAL hMem,
 _In_  SIZE_T uBytes,
 _In_  UINT uFlags
 );
 *
 */

void LocalReAlloc_handler(void *opaque) {
	gva_t stack[4];
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 4, stack);
	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {

		Heap_Info * hi = (Heap_Info *) *it;
		if (hi->addr == stack[1]) {
			hi->len = stack[2];
			break;
		}
	}

}

void malloc_handler_ret(void *opaque)
{
	uint32_t len;
	 target_ulong heap_addr;
	 alloc_ctx *ctx = (alloc_ctx*)opaque;
	 len = ctx->len;
	 heap_addr = cpu_single_env->regs[R_EAX];

	// if( len< 8) //if heap size is too small, ignore it
	//	 return;
	 Heap_Info * hi = (Heap_Info *) malloc(sizeof(Heap_Info));
	 hi->addr = heap_addr;
	 hi->len  = len;
	 hi->status = 1;
	 heap_list.push_back(hi);


	 DECAF_printf("HEAP 0x%08x LEN %d  %s\n", heap_addr, len, current_step_trace.c_str());
	 hookapi_remove_hook(ctx->hook_handle);

	 free(ctx);
}
/*
void *malloc( size_t size );
*/
void malloc_handler(void *opaque)
{
	gva_t stack[2];
	alloc_ctx * actx =(alloc_ctx*) g_malloc(sizeof(alloc_ctx));
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*2, stack);

	actx->len = stack[1];
	actx->hook_handle = hookapi_hook_return(stack[0],malloc_handler_ret, actx, sizeof(*actx));
	

}
/*
void* calloc (size_t num, size_t size);
*/
void calloc_handler(void *opaque)
{
	gva_t stack[3];

	alloc_ctx * actx =(alloc_ctx*) g_malloc(sizeof(alloc_ctx));
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*3, stack);

	actx->len = stack[1]*stack[2];
	actx->hook_handle = hookapi_hook_return(stack[0],malloc_handler_ret, actx, sizeof(*actx));


}
void free_handler(void *opaque)
{
	gva_t stack[2];

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 2, stack);

	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {
		Heap_Info * hi = (Heap_Info *) *it;

		if (hi->addr == stack[1]) {
			hi->status = 0;
			break;
		}
	}
	DECAF_printf("FREE 0x%08x  %s\n", stack[1], current_step_trace.c_str());
	//DECAF_printf("HEAP FREE \n");
}
/*
void* realloc (void* ptr, size_t size);
*/
void realloc_handler(void *opaque)
{
	gva_t stack[3];
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 3, stack);

	for (std::list<Heap_Info *>::iterator it = heap_list.begin();
			it != heap_list.end(); ++it) {
		Heap_Info * hi = (Heap_Info *) *it;

		if (hi->addr == stack[1]) {
			hi->status = 1;
			hi->len = stack[2];
			break;
		}
	}

//	DECAF_printf("HEAP REALLOC \n");
}


void _MemRealloc_op_handler_ret(void *opaque)
{
	std::map<gva_t,Heap_Info *>::iterator it;

	//keep record of heap range for better memory lookup
	realloc_ctx * rctx = (realloc_ctx *) opaque;

	gva_t heap_addr = cpu_single_env->regs[R_EAX];


	if(heap_addr == 0)
		return;

	if( heap_start != 0)
	{
		if(heap_addr < heap_start)
			heap_start = heap_addr;
		if(heap_end < heap_addr + rctx->len)
			heap_end = heap_addr + rctx->len;
	}
	else
	{
		heap_start = heap_addr;
		heap_end = heap_addr + rctx->len;
	}


	if( heap_addr != rctx->addr)
		DECAF_printf("relaloc different heap object 0x%08x 0x%08x \n", rctx->addr, heap_addr);


	it = heap_map.find(heap_addr);

	if( it != heap_map.end())
	{
		Heap_Info * hi = it->second;
		hi->status = 1;
		hi->len = rctx->len;
	}
	else
	{
	//	DECAF_printf("Unrecored heap realloc \n");

		Heap_Info * hi = (Heap_Info *) g_malloc(sizeof(Heap_Info));
		hi->len = rctx->len;
		hi->status = 1;
		hi->addr = heap_addr;

		heap_map.insert(std::pair<gva_t,Heap_Info*>(heap_addr, hi));
	}

	hookapi_remove_hook(rctx->hook_handle);
	free(rctx);

}

//int __stdcall _MemRealloc(int, SIZE_T dwBytes)
void _MemRealloc_op_handler(void *opaque)
{
	gva_t stack[3];
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 3, stack);
	realloc_ctx *rctx = (realloc_ctx *) g_malloc(sizeof(realloc_ctx));
	rctx->len = stack[2];
	rctx->addr = stack[1];

	rctx->hook_handle =  hookapi_hook_return(stack[0],_MemRealloc_op_handler_ret, rctx, sizeof(*rctx));


}

void new_op_handler_ret(void *opaque)
{
	std::map<gva_t,Heap_Info *>::iterator it;
	new_ctx *nctx = (new_ctx*)opaque;
	gva_t heap_addr = cpu_single_env->regs[R_EAX];
	//DECAF_printf("new object 0x%08x  Len 0x%08x \n", heap_addr, nctx->len );

	//keep record of heap range for better memory lookup

	if( heap_start != 0)
	{
		if(heap_addr < heap_start)
			heap_start = heap_addr;
		if(heap_end < heap_addr + nctx->len)
			heap_end = heap_addr + nctx->len;
	}
	else
	{
		heap_start = heap_addr ;
		heap_end = heap_start + nctx->len;
	}


	//insert new allocated object into heap_map
	

	it = heap_map.find(heap_addr);
	
	if(it != heap_map.end()) //already exists 
	{
		Heap_Info * hi = it->second;
		hi->status = 1 ;
		hi->len = nctx->len;
	}
	else
	{ //not exists 

		Heap_Info * hi = (Heap_Info *) g_malloc(sizeof(Heap_Info));
		hi->len = nctx->len;
		hi->status = 1;
		hi->addr = heap_addr;

		heap_map.insert(std::pair<gva_t,Heap_Info*>(heap_addr, hi));


	}

	hookapi_remove_hook(nctx->hook_handle);

	free(nctx);

}
//void *new(uint)

void new_op_handler(void *opaque)
{
	
	gva_t stack[2];
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 3, stack);
	new_ctx *nctx = (new_ctx *) g_malloc(sizeof(new_ctx));
	nctx->len = stack[1];
	nctx->hook_handle =  hookapi_hook_return(stack[0],new_op_handler_ret, nctx, sizeof(*nctx));
	

}
//void delete(void *)
void delete_op_handler(void *opaque)
{
	std::map<gva_t,Heap_Info *>::iterator it;
	gva_t stack[2];
	gva_t heap_addr = cpu_single_env->regs[R_EAX];
	DECAF_read_mem(NULL, heap_addr, 4 * 3, stack);
//	DECAF_printf("FREE 0x%08x\n", stack[1]);

	it = heap_map.find(heap_addr);

	if( it != heap_map.end())
	{
		Heap_Info * hi = it->second;
		hi->status = 0;

	}
	else{

	//	DECAF_printf("Freed object is not recorded in heap_map \n");
	}




}

void clean_up_trace()
{
	if(bin_trace_log)
	{
		fwrite(mem_record_list,sizeof(Mem_Record), MEM_RECORD_INDEX, bin_trace_log);
		MEM_RECORD_INDEX = 0;
		fclose(bin_trace_log);
	}
}