import sys
import os
import time
import subprocess
import shutil
from struct import *
from sets import Set
class JS_Bin:
	ENTRY_SIZE = 7

	def __init__(self, filename):
		self.filename = filename
		self.two_level_mem_map = dict()
		self.first_level_mem_map = dict()
		#self.ENTRY_SIZE = 7

#bin structure
#typedef struct{
#	gva_t vaddr;
#	uint32_t value;
#	uint32_t size;
#	uint32_t type; //1 for mem_read 2 for mem_write 3 for block record
#	uint32_t cur_eip;
#	uint32_t call_stack[2];
#} Mem_Record;
# return a list containing all mem read/write operations
# for every elements of the list, it stores the tuple.
#(read/write, vaddr, cur_eip, [stacktop], [stacktop-1])
#return: a list
	def get_rw_list(self):
		
		R_W_list = []
		f = open(self.filename,"rb")
		content = f.read()
		
		mem_op_count = len(content)/(4*self.ENTRY_SIZE)
		result = unpack_from("<"+str(mem_op_count*self.ENTRY_SIZE)+"I",content)
		index = 0
		while index < mem_op_count:
			vaddr = result[index* self.ENTRY_SIZE]
			value = result[index*self.ENTRY_SIZE + 1]
			size = result[index*self.ENTRY_SIZE + 2]
			r_w = result[index*self.ENTRY_SIZE + 3 ] 
			cur_eip = result[index * self.ENTRY_SIZE + 4]
			stack1 = result[index * self.ENTRY_SIZE + 5]
			stack2 = result[index * self.ENTRY_SIZE +6 ]

			R_W_list.append((vaddr,value,size,r_w, cur_eip, stack1, stack2))
			index = index + 1
		f.close()
		return R_W_list

	def get_rw_set(self):
		R_W_set = Set()
		f = open(self.filename,"rb")
		content = f.read()
		mem_op_count = len(content)/(4*self.ENTRY_SIZE)
		result = unpack_from("<"+str(mem_op_count*self.ENTRY_SIZE)+"I",content)
		index = 0
		while index < mem_op_count:
			r_w = result[index*self.ENTRY_SIZE + 3 ] 
			vaddr = result[index* self.ENTRY_SIZE]
			cur_eip = result[index * self.ENTRY_SIZE + 4]
			stack1 = result[index * self.ENTRY_SIZE + 5]
			stack2 = result[index * self.ENTRY_SIZE +6 ]
			if cur_eip >=0x6d040000 and cur_eip <=(0x6d040000 + 0x1a000):
				print "stub.dll"+ str(hex(cur_eip))
			R_W_set.add((r_w, vaddr, cur_eip, stack1, stack2))
			index = index + 1
		f.close()
		return R_W_set


	def compress_bin(self):
		print self.filename
		R_W_list = []
		f = open(self.filename,"rb")
		content = f.read()
		mem_op_count = len(content)/(4*7)
		result = unpack_from("<"+str(mem_op_count*7)+"I",content)
		index = 0
		isRWListEmpty = True
		while index < mem_op_count:
			if result[index*7+3] == 1: #Mem read
				vaddr = result[index*7]
				size = result[index*7 + 2]
				if not isRWListEmpty:
					t1 = R_W_list[len(R_W_list)-1]
					if t1[2] == 2: #last mem opration is write,so we create a new memread
						R_W_list.append((vaddr,size,1))
						continue
					if t1[0] <= vaddr and (t1[0]+t1[1]) >= vaddr:
						R_W_list[len(R_W_list) -1] = (t1[0],vaddr+size -t1[0],1)

					else:
						R_W_list.append((vaddr, size, 1)) #//need check if there is ovelap
				else:
					R_W_list.append((vaddr, size, 1))
					isRWListEmpty = False
				
			elif result[index*7+3] == 2: #Mem Write
				vaddr = result[index*7]
				size = result[index*7 + 2]
				if not isRWListEmpty:
					t1 = R_W_list[len(R_W_list)-1]
					if t1[2] == 1: #last mem opreation is read, so we create a new memwrite
						R_W_list.append((vaddr, size, 2))
						continue
					if t1[0] <= vaddr and (t1[0]+t1[1]) >= vaddr:
						R_W_list[len(R_W_list) -1] = (t1[0],vaddr+size -t1[0],2)

					else:
						R_W_list.append((vaddr, size, 2)) #//need check if there is ovelap
				else:
					R_W_list.append((vaddr, size, 2))
			index = index + 1
			#if len(R_W_list) == 40:
			#	print R_W_list
		print "done "+str(index) +" "+ str(len(R_W_list))
		return R_W_list
	# get "read" opreatoin whose data is not written within current JS statement
	def filter_read(self, R_W_list):
		print len(R_W_list)
		filter_len = 0
		for idx,val in enumerate(R_W_list):
			if val[2] == 1: #mem read
				iswithinJS = False
				for i in range(idx,0, -1):
					tuple1 = R_W_list[i]
					if tuple1[2] == 2 and tuple1[0] <= val[0] and tuple1[0] + tuple1[1] >= val[0] + val[1]:
						iswithinJS = True
						break
				if not iswithinJS:
					print "not within js "+ str(hex(val[0]))
					filter_len = filter_len + 1
		print filter_len








