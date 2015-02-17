
#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "utils/Output.h"
#include "utils.h"


int readwstr(target_ulong addr, void *buf)
{
	//bytewise for now, perhaps block wise later.
	char *store = (char *) buf;
	int i = -1;
	do {

		 if(++i == MAX_NAME_LENGTH)
			break;

		if(DECAF_read_mem(cpu_single_env, addr+(2*i), 1,(uint8_t *)&store[i]) < 0) {
			store[i] = '\0';
			return i;
		}


	} while (store[i] != '\0');

	if(i == MAX_NAME_LENGTH) {
		store[i-1] = '\0';
	}
	return i-1;
}
// len  equals (string_len *2)
// buf size equals len/2+1
int readwstr_with_len(target_ulong addr,void *buf, uint32_t len)
{
	//bytewise for now, perhaps block wise later.
	char *store = (char *) buf;
	char *mem ;
	int ret;
	if(len <2)
		return 0;

	mem= (char*) malloc(len);
	memset(mem,0, len);
	ret = DECAF_read_mem(cpu_single_env, addr, len,(void *) mem);

	int i = -1;
	do {
		i++;
		store[i] = mem[2*i];
	} while (i<len/2-1);
	store[len/2] = '\0';
	free(mem);
	return i-1;
}
int readcstr(target_ulong addr, void *buf)
{
	//bytewise for now, perhaps block wise later.
	char *store = (char *) buf;
	int i = -1;
	do {
		if(++i == MAX_NAME_LENGTH)
			break;

		if(DECAF_read_mem(cpu_single_env, addr+i, 1,(uint8_t *)&store[i]) < 0) {
			store[i] = '\0';
			return i;
		}

	} while (store[i] != '\0');

	if(i == MAX_NAME_LENGTH) {
		store[i-1] = '\0';
	}
	return i-1;
}
