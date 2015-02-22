import sys
import os
import time
from datetime import datetime
import subprocess
import shutil
import gc
from struct import *
from JS_Bin import JS_Bin
from sets import Set
import pickle
from distorm3 import *
BB_FILE_LOC = "/home/smarabbit/work/decaf/trunk/i386-softmmu/bblist.txt"
BB_CODE_LOC = "/home/smarabbit/work/decaf/trunk/i386-softmmu/"
MEM_DUMP_LOC = "./test/cve20100806/virtualmemory.bin"
BBLIST = dict()
TAINTED_INSN = []
OPERAND_NONE = ""
OPERAND_IMMEDIATE = "Immediate"
OPERAND_REGISTER = "Register"
# the operand is a memory address
OPERAND_ABSOLUTE_ADDRESS = "AbsoluteMemoryAddress" # The address calculated is absolute
OPERAND_MEMORY = "AbsoluteMemory" # The address calculated uses registers expression
OPERAND_FAR_MEMORY = "FarMemory" # like absolute but with selector/segment specified too
MAX_ESP = 0xFFFFFFFF
# pdm.dll:0x4a000000 stub.dll 0x6d040000 msdbg.dll 0x4aa00000
# NetBeansExtension.dll 0x10000000
#jscript.dll 0x75c50000
# this is for ie6/7,winxp3
WHITE_LIST = [(0x4a000000,0x2c000),(0x6d040000,0x1a000),(0x4aa00000,0x15000),(0x10000000, 0x16000),(0x75c50000,0x0007d000)]

#pdm.dll, stub.dll,msdgb.dll,msdbg2.dll,jscript.dll
WHITE_LIST = [(0x3f320000,0x00058000), (0x6d040000,0x0001a000),(0x4aa00000,0x00015000),(0x3f0e0000,0x00042000),(0x10000000,0x00016000),(0x63380000,0x000b4000)]
#code region for ie6 winxp3 

'''
CODE_MODULE_LIST = [(0x00400000,0x00019000),(0x00df0000,0x002c5000),(0x01ef0000,0x00017000),(0x10000000,0x00016000),\
(0x4a000000,0x0002c000),(0x4aa00000,0x00015000),(0x5ad70000,0x00038000),(0x5b860000,0x00055000),(0x5cb70000,0x00026000),\
(0x5d090000,0x0009a000),(0x662b0000,0x00058000),(0x66e50000,0x00040000),(0x6d040000,0x0001a000),(0x71600000,0x00012000),\
(0x71800000,0x00088000),(0x71a50000,0x0003f000),(0x71a90000,0x00008000),(0x71aa0000,0x00008000),(0x71ab0000,0x00017000),\
(0x71ad0000,0x00009000),(0x71b20000,0x00012000),(0x71bf0000,0x00013000),(0x71c10000,0x0000e000),(0x71c80000,0x00007000),\
(0x71c90000,0x00040000),(0x71cd0000,0x00017000),(0x722b0000,0x00005000),(0x73000000,0x00026000),(0x73d70000,0x00013000),\
(0x74320000,0x0003d000),(0x746c0000,0x00027000),(0x746f0000,0x0002a000),(0x74720000,0x0004c000),(0x74980000,0x00113000),\
(0x74e30000,0x0006d000),(0x754d0000,0x00080000),(0x75970000,0x000f8000),(0x75c50000,0x0007d000),(0x75cf0000,0x00091000),\
(0x75f60000,0x00007000),(0x75f70000,0x0000a000),(0x75f80000,0x000fd000),(0x76360000,0x00010000),(0x76390000,0x0001d000),\
(0x763b0000,0x00049000),(0x76600000,0x0001d000),(0x769c0000,0x000b4000),(0x76b40000,0x0002d000),(0x76bf0000,0x0000b000),\
(0x76c30000,0x0002e000),(0x76c90000,0x00028000),(0x76d60000,0x00019000),(0x76e80000,0x0000e000),(0x76e90000,0x00012000),\
(0x76eb0000,0x0002f000),(0x76ee0000,0x0003c000),(0x76f60000,0x0002c000),(0x76fd0000,0x0007f000),(0x77050000,0x000c5000),\
(0x77120000,0x0008b000),(0x771b0000,0x000aa000),(0x773d0000,0x00103000),(0x774e0000,0x0013d000),(0x77920000,0x000f3000),\
(0x77a20000,0x00054000),(0x77a80000,0x00095000),(0x77b20000,0x00012000),(0x77b40000,0x00022000),(0x77c00000,0x00008000),\
(0x77c10000,0x00058000),(0x77c70000,0x00024000),(0x77dd0000,0x0009b000),(0x77e70000,0x00092000),(0x77f10000,0x00049000),\
(0x77f60000,0x00076000),(0x77fe0000,0x00011000),(0x78050000,0x00069000),(0x78a60000,0x00026000),(0x78aa0000,0x000bf000),\
(0x7c800000,0x000f6000),(0x7c900000,0x000af000),(0x7c9c0000,0x00817000),(0x7dc30000,0x002f2000),(0x7e1e0000,0x000a2000),\
(0x7e290000,0x00171000),(0x7e410000,0x00091000),(0x7e720000,0x000b0000)]
'''
'''
#code region for ie7 winxp3
CODE_MODULE_LIST = [(0x00400000,0x0009a000),(0x00a30000,0x005c9000),(0x01240000,0x002c5000),(0x01c10000,0x00009000),\
(0x47060000,0x00021000),(0x4a000000,0x0002c000),(0x4aa00000,0x00015000),(0x4ec50000,0x001a6000),(0x5ad70000,0x00038000),\
(0x5b860000,0x00055000),(0x5cb70000,0x00026000),(0x5d090000,0x0009a000),(0x5dca0000,0x00045000),(0x5dff0000,0x0002f000),\
(0x61410000,0x00124000),(0x61930000,0x0004a000),(0x662b0000,0x00058000),(0x6f880000,0x001ca000),(0x71a50000,0x0003f000),\
(0x71a90000,0x00008000),(0x71aa0000,0x00008000),(0x71ab0000,0x00017000),(0x71bf0000,0x00013000),(0x71d40000,0x0001b000),\
(0x722b0000,0x00005000),(0x72ea0000,0x00060000),(0x746c0000,0x00029000),(0x746f0000,0x0002a000),(0x74720000,0x0004c000),\
(0x755c0000,0x0002e000),(0x75c50000,0x0007d000),(0x75cf0000,0x00091000),(0x76380000,0x00005000),(0x76390000,0x0001d000),\
(0x76600000,0x0001d000),(0x769c0000,0x000b4000),(0x76b40000,0x0002d000),(0x76bf0000,0x0000b000),(0x76c30000,0x0002e000),\
(0x76c90000,0x00028000),(0x76cc0000,0x0000b000),(0x76d60000,0x00019000),(0x76e80000,0x0000e000),(0x76e90000,0x00012000),\
(0x76eb0000,0x0002f000),(0x76ee0000,0x0003c000),(0x76f60000,0x0002c000),(0x76fc0000,0x00006000),(0x76fd0000,0x0007f000),\
(0x77050000,0x000c5000),(0x77120000,0x0008b000),(0x771b0000,0x000ce000),(0x773d0000,0x00103000),(0x774e0000,0x0013d000),\
(0x77690000,0x00021000),(0x77920000,0x000f3000),(0x77a20000,0x00054000),(0x77a80000,0x00095000),(0x77b20000,0x00012000),\
(0x77b40000,0x00022000),(0x77be0000,0x00015000),(0x77c00000,0x00008000),(0x77c10000,0x00058000),(0x77c70000,0x00024000),\
(0x77dd0000,0x0009b000),(0x77e70000,0x00092000),(0x77f10000,0x00049000),(0x77f60000,0x00076000),(0x77fe0000,0x00011000),\
(0x7c800000,0x000f6000),(0x7c900000,0x000af000),(0x7c9c0000,0x00817000),(0x7e410000,0x00091000),(0x7e720000,0x000b0000),\
(0x7e830000,0x0036f000)]
'''
#code region for ie8 CVE 20133163
CODE_MODULE_LIST = [(0x00400000,0x0009c000),(0x00930000,0x00009000),(0x00970000,0x00006000),(0x00e30000,0x002c5000),\
(0x01120000,0x00a91000),(0x022c0000,0x0002a000),(0x03040000,0x00040000),(0x03410000,0x000bf000),(0x034d0000,0x00029000),\
(0x03ce0000,0x00099000),(0x04880000,0x00094000),(0x10000000,0x00016000),(0x1a400000,0x00132000),(0x3f0e0000,0x00042000),\
(0x3f320000,0x00058000),(0x47060000,0x00021000),(0x4aa00000,0x00015000),(0x5ad70000,0x00038000),(0x5b860000,0x00055000),\
(0x5d090000,0x0009a000),(0x5dca0000,0x001e8000),(0x62c70000,0x00019000),(0x63000000,0x000e6000),(0x63380000,0x000b4000),\
(0x63580000,0x005ac000),(0x662b0000,0x00058000),(0x68000000,0x00036000),(0x6cd00000,0x00024000),(0x6d040000,0x0001a000),\
(0x6d1d0000,0x0005c000),(0x6e1e0000,0x0002e000),(0x6e5c0000,0x00074000),(0x71a50000,0x0003f000),(0x71a90000,0x00008000),\
(0x71aa0000,0x00008000),(0x71ab0000,0x00017000),(0x71d40000,0x0001b000),(0x722b0000,0x00005000),(0x72ea0000,0x0006f000),\
(0x73760000,0x0004b000),(0x73bc0000,0x00006000),(0x746f0000,0x0002a000),(0x74720000,0x0004c000),(0x74980000,0x00113000),\
(0x74c80000,0x0002c000),(0x74d90000,0x0006b000),(0x755c0000,0x0002e000),(0x75cf0000,0x00091000),(0x76080000,0x00065000),\
(0x76380000,0x00005000),(0x76390000,0x0001d000),(0x763b0000,0x00049000),(0x76600000,0x0001d000),(0x769c0000,0x000b4000),\
(0x76b40000,0x0002d000),(0x76bf0000,0x0000b000),(0x76d60000,0x00019000),(0x76e80000,0x0000e000),(0x76e90000,0x00012000),\
(0x76eb0000,0x0002f000),(0x76ee0000,0x0003c000),(0x76f20000,0x00027000),(0x76fc0000,0x00006000),(0x76fd0000,0x0007f000),\
(0x77050000,0x000c5000),(0x77120000,0x0008b000),(0x773d0000,0x00103000),(0x774e0000,0x0013d000),(0x77920000,0x000f3000),\
(0x77a20000,0x00054000),(0x77a80000,0x00095000),(0x77b20000,0x00012000),(0x77b40000,0x00022000),(0x77c00000,0x00008000),\
(0x77c10000,0x00058000),(0x77c70000,0x00024000),(0x77dd0000,0x0009b000),(0x77e70000,0x00092000),(0x77f10000,0x00049000),\
(0x77f60000,0x00076000),(0x77fe0000,0x00011000),(0x78050000,0x00069000),(0x78a60000,0x00026000),(0x78aa0000,0x000bf000),\
(0x7c800000,0x000f6000),(0x7c900000,0x000af000),(0x7c9c0000,0x00817000),(0x7e410000,0x00091000),(0x7e720000,0x000b0000)]



#typedef struct{
#        gva_t vaddr;
#        uint32_t value;
#        uint32_t size;
#        uint32_t type; //1 for mem_read 2 for mem_write
#        uint32_t cur_eip;
#        uint32_t call_stack[2];
#} Mem_Record;
def isInWhiteList(eip):
	#WHITE_LIST = []
	for e in WHITE_LIST:
		if eip >= e[0] and eip <= e[0] + e[1]:
			return True
	return False

def readInsn(file,eip,size):
	if BBLIST.has_key(eip):
		return BBLIST[eip]

	if not os.path.exists(file):
		print "code file not exists, ERROR"
		sys.exit()
		return
	f = open(file,'rb')
	f.seek(eip,0)
	code = f.read(size)
	f.close()

	l = Decompose(eip,code,Decode32Bits)
	BBLIST[eip]=l
	return l




#writ the basic block info to a binary file.
def write2file(eip,size):
	if os.path.exists(BB_CODE_LOC+str(hex(eip))[2:]+".bin"):
		return
	f = open(BB_FILE_LOC,'w+')
	f.write(bytearray(pack("<i",eip)+pack("<i",size)))
	f.close()
	time.sleep(1)

def getInsList(file,eip):
	f = open(file,"rb")
	c = f.read()
	f.close()
	l = Decompose(eip, c, Decode32Bits)
	#ll = Decode(eip,c,Decode32Bits)
	#print ll
	BBLIST[eip]=l
	return l
def sliceIns(sink, ins,mrw):
	#print str(hex(ins.address))+" "+ str(ins)
	#print mrw
	#print " sink " 
	#printHexTuple(sink)
	global MAX_ESP
	cur_esp = 0
	if len(mrw) != 0:
		cur_esp = mrw[0][5]
		if MAX_ESP >cur_esp:
			MAX_ESP = cur_esp
	isTainted = False
	if sink == None:
		return
	if isInWhiteList(ins.address):
		return sink

	if not Mnemonics.has_key(ins.opcode):
		print "Opcode not exist, maybe casused by swapped out memory."
		os.sys.exit()
	name = Mnemonics[ins.opcode]
	oper = ins.operands
	if name in {"MOV","LEA","MOVZX","MOVSX"}:
		if oper[0].type == OPERAND_REGISTER: # MOV reg,xx
			union = isInSink(sink,OPERAND_REGISTER,oper[0].index,0,0)
			if len(union)!=0:
				sink.difference_update(union)
				sink.update(getSinkFromOperand(oper[1], ins.address,mrw, 1,[0,1,2,3]))
				isTainted = True
		elif oper[0].type == OPERAND_MEMORY: # MOV [xx],xx
			for v in mrw:
				if v[3] == 2: #mem write
					union = isInSink(sink,OPERAND_ABSOLUTE_ADDRESS,v[0],v[1],v[2])
					if len(union)!=0:
						sink.difference_update(union)
						sink.update(getSinkFromOperand(oper[1], ins.address, mrw,1,[0,1,2,3]))
						sink.update(getSinkFromOperand(oper[0], ins.address,mrw,3,[0,1,2,3]))
						isTainted = True
						#print "MOV [xx],xx  [xx] is read by later instruction"
	#elif name in {"MOVZX","MOVSX"}:
	#	print "MOVZX"

	#elif name in {"MOVSB","MOVSD","MOVSW"}:
	#	print "MOVE STRING"
	elif name in {"MUL","DIV","IDIV"}:# MUL x : EDX:EAX = EAX * x or DX:AX = AX * x or AX = AL * x
		#union = isInSink(sink,OPERAND_REGISTER, Registers.index(""))
		#os.system("echo "+ str(oper[0].size)+ " >c.txt")
		size = oper[0].size/8
		union = Set()
		if size == 1:
			union.update(isInSink(sink, OPERAND_REGISTER, Registers.index("AX"),0,0))
		elif size == 2:
			union.update(isInSink(sink,OPERAND_REGISTER, Registers.index("AX"),0,0))
			union.update(isInSink(sink,OPERAND_REGISTER, Registers.index("DX"),0,0))
		elif size == 4:
			union.update(isInSink(sink, OPERAND_REGISTER, Registers.index("EAX"),0,0))
			union.update(isInSink(sink, OPERAND_REGISTER, Registers.index("EDX"),0,0))
		if len(union) != 0:
			sink.update(getSinkFromOperand(oper[0], ins.address, mrw,1,[0,1,2,3]))
			isTainted = True
	elif name in {"IMUL"}:
		if len(oper) == 1: #IMUL X:  EDX:EAX = EAX * x or DX:AX = AX * x or AX = AL * x
			size = oper[0].size/8
			union = Set()
			if size == 1:
				union.update(isInSink(sink, OPERAND_REGISTER, Registers.index("AX"),0,0))
			elif size == 2:
				union.update(isInSink(sink,OPERAND_REGISTER, Registers.index("AX"),0,0))
				union.update(isInSink(sink,OPERAND_REGISTER, Registers.index("DX"),0,0))
			elif size == 4:
				union.update(isInSink(sink, OPERAND_REGISTER, Registers.index("EAX"),0,0))
				union.update(isInSink(sink, OPERAND_REGISTER, Registers.index("EDX"),0,0))
			if len(union) != 0:
				sink.update(getSinkFromOperand(oper[0], ins.address, mrw,1,[0,1,2,3]))
		elif len(oper) == 2: #IMUL A ,B:
			if oper[0].type ==OPERAND_REGISTER: # for this case, A could only be register
				union = isInSink(sink, OPERAND_REGISTER, oper[0].index, 0,0)
				if len(union) != 0:
					sink.update(getSinkFromOperand(oper[1],ins.address, mrw,1, [0,1,2,3]))
					isTainted = True

		elif len(oper) == 3: #IMUL A,B,im A = B*im , A could only be register
			if oper[0].type == OPERAND_REGISTER:
				union = isInSink(sink,OPERAND_REGISTER, oper[0].index, 0,0)
				if len(union) != 0:
					sink.difference_update(union)
					sink.update(getSinkFromOperand(oper[1],ins.address, mrw,1,[0,1,2,3]))
					isTainted = True
			



		
	elif name in {"ADC","ADD","SUB","AND","SBB","OR"}:
		if oper[0].type == OPERAND_REGISTER: # ADD reg,xx
			union = isInSink(sink,OPERAND_REGISTER,oper[0].index,0,0)
			if len(union) != 0:
				sink.update(getSinkFromOperand(oper[1],ins.address,mrw, 1,[0,1,2,3]))
				isTainted = True
		elif oper[0].type == OPERAND_MEMORY: # add [REG],XX
			for v in mrw:
				if v[3] == 2: #mem wirte
					union = isInSink(sink,OPERAND_ABSOLUTE_ADDRESS,v[0],v[1],v[2])
					if len(union) != 0:
						#sink.difference_update(union)
						sink.update(getSinkFromOperand(oper[1], ins.address, mrw,1,[0,1,2,3]))
						sink.update(getSinkFromOperand(oper[0], ins.address,mrw,3,[0,1,2,3]))
						isTainted = True
						#print name +" [xx],xx  [xx] is read by later instruction"
	elif name in {"XOR"}:# xor clear the value oper1 and oper2 is the same.
		if oper[0].type == OPERAND_REGISTER and oper[1].type == OPERAND_REGISTER and oper[0].index == oper[1].index:
			union = isInSink(sink, OPERAND_REGISTER,oper[0].index, 0, 0)
			if len(union) != 0:
				sink.difference_update(union)
				isTainted = True
		elif oper[0].type == OPERAND_REGISTER:
			union = isInSink(sink, OPERAND_REGISTER, oper[0].index,0,0)
			if len(union) != 0 :
				sink.update(getSinkFromOperand(oper[1],ins.address, mrw,1,[0,1,2,3]))
				isTainted = True
		elif oper[0].type == OPERAND_MEMORY:
			for v in mrw:
				if v[3] == 2: #mem wirte
					union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS, v[0],v[1],v[2])
					if len(union) != 0:
						sink.difference_update(union)
						sink.update(getSinkFromOperand(oper[1], ins.address, mrw,1,[0,1,2,3]))
						sink.update(getSinkFromOperand(oper[0], ins.address,mrw,3,[0,1,3,3]))
						isTainted = True
						#print name +" [xx],xx  [xx] is read by later instruction"
	elif name in {"SHL"}:
		if oper[1].value >=8:# shift more than one byte
			if oper[0].type == OPERAND_REGISTER:
				union = isInSink(sink, OPERAND_REGISTER,oper[0].index,0,0)
				if len(union) !=0:
					isTainted = True
					s = union.pop() # 
					regindex = s[1] # regindex 
					union.add(s)
					for i in range(int(oper[1].value/8),0,-1):
						if (OPERAND_REGISTER, regindex,4-i) in union:
							sink.remove((OPERAND_REGISTER,regindex,4-i))
			elif oper[0].type == OPERAND_MEMORY:
				for v in mrw:
					if v[3] == 2: #mem wirte
						union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS, v[0],v[1],v[2])
						if len(union) != 0:
							isTainted = True
							dele = []
							for i in range(int(oper[1].value/8),0,-1):
								dele.add(v[0]+4-i)
							for e in union:
								if e[1] in dele:
									sink.remove(e)
	elif name in {"SHR"}:
		if oper[1].value >=8:# shift more than one byte
			if oper[0].type == OPERAND_REGISTER:
				union = isInSink(sink, OPERAND_REGISTER,oper[0].index,0,0)
				if len(union) !=0:
					isTainted = True
					s = union.pop() # 
					regindex = s[1] # regindex 
					union.add(s)
					for i in range(int(oper[1].value/8),0,-1):
						if (OPERAND_REGISTER, regindex,i-1) in union:
							sink.remove((OPERAND_REGISTER,regindex,i-1))
			elif oper[0].type == OPERAND_MEMORY:
				for v in mrw:
					if v[3] == 2: #mem wirte
						union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS, v[0],v[1],v[2])
						if len(union) != 0:
							isTainted = True
							dele = []
							for i in range(int(oper[1].value/8),0,-1):
								dele.add(v[0]+i-1)
							for e in union:
								if e[1] in dele:
									sink.remove(e)





	elif name == "POP":
		#print "POP"
		if oper[0].type == OPERAND_REGISTER: # POP reg
			union = isInSink(sink, OPERAND_REGISTER, oper[0].index,0,0)
			if len(union) != 0:
				sink.difference_update(union)
				for v in mrw:
					if v[3] == 1: # mem read
						#sink.add((OPERAND_ABSOLUTE_ADDRESS,v[0],v[1]))
						sink.update(getSinkFromMemory(v,[0,1,2,3]))
				isTainted = True
		elif oper[0].type == OPERAND_MEMORY: # pop [reg]
			for v in mrw:
				if v[3] == 2: #mem write
					union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS, v[0],v[1],v[2])
					if len(union) != 0:
						sink.difference_update(union)
						#sink.update(getSinkFromOperand(oper[1], ins.address, mrw,1,[0,1,2,3]))
						sink.update(getSinkFromOperand(oper[0], ins.address,mrw,3,[0,1,2,3]))
						isTainted = True
			if isTainted:
				for v in mrw:
					if v[3] == 1: #mem read
						if not isInWhiteList(ins.address):
							sink.update(getSinkFromMemory(v,[0,1,2,3]))
		isTainted = False # ingore pop instruction in tainted instruction
	elif name == "PUSH":
		#print "PUSH"
		for v in mrw:
			if v[3] == 2: #mem write
				union = isInSink(sink,OPERAND_ABSOLUTE_ADDRESS,v[0],v[1],v[2])
				if len(union) != 0:
					sink.difference_update(union)
					sink.update(getSinkFromOperand(oper[0], ins.address, mrw, 1,[0,1,2,3]))
					isTainted = True

	elif name in {"CMPXCHG"}:
		union = getSinkFromOperand(oper[0],ins.address,mrw,2,[0,1,2,3])
		union.update(getSinkFromOperand(oper[1],ins.address,mrw,2,[0,1,2,3]))
		sink.difference_update(union)


	elif name in {"CMPXCHG8B"}: #CMPXCHG8B m64
		isWrite2Dest  = False
		for v in mrw:
			if v[3] ==2 : #mem write
				isWrite2Dest = True
				break
		if isWrite2Dest:
			union = isInSink(sink,OPERAND_REGISTER,Registers.index("EBX"),0,0)
			union.update(isInSink(sink,OPERAND_REGISTER,Registers.index("ECX"),0,0))
			if len(union) !=0:
				sink.difference_update(union)
				isTainted = True
				#sink.update(getSinkFromOperand(oper[0],ins.address,mrw,2,[0,1,2,3]))
		else:
			for v in mrw:
				if v[3] == 1: #mem read
					union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS, v[0], v[1], v[2])
					if len(union) != 0:
						isTainted = True
						sink.difference_update(union)
						#sink.update(getSinkFromRegister(Registers.index("EDX"),[0,1,2,3]))
						#sink.update(getSinkFromRegister(Registers.index("EAX"),[0,1,2,3]))

	elif name in {"XCHG","XADD"}:
		union = getSinkFromOperand(oper[1],ins.address, mrw,1,[0,1,2,3]) #source
		temp = union.intersection(sink)
		union0 = getSinkFromOperand(oper[0],ins.address,mrw,1,[0,1,2,3])
		temp0 = union.intersection(sink)
		if len(temp) != 0 and len(temp0) ==0 :
			isTainted = True
			sink.difference_update(temp)
			sink.update(getSinkFromOperand(oper[0],ins.address,mrw,2,[0,1,2,3]))
		elif len(temp) == 0 and len(temp0) != 0:
			isTainted = True
			sink.difference_update(temp0)
			sink.update(getSinkFromOperand(oper[1],ins.address,mrw,2,[0,1,2,3]))
		
	elif name in {"CALL"}:
		if cur_esp != 0:
			sink = clear_stack(sink, cur_esp, MAX_ESP)
			MAX_ESP = cur_esp

	elif name in {"INC", "NEG","DEC","NOT","ROL","RCL","ROR","RCR","TEST",\
					"AAA","AAD","AAS","BT","BTC","BTR","BTS","CALL","CBW"\
					"CWDE","CLC","CLD","CLI","CMC","CMOVA","CMPXCHG"}:#CMOVA not clear 
		#do nothing
		sink = sink


# if the instruction write to memory read by later instruction
	else:
		for v in mrw:
			if v[3] == 2: # mem write
				union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS, v[0], v[1], v[2])
				if len(union) != 0:
					sink.difference_update(union)
					sink.update(getSinkFromIns(ins, mrw))
					isTainted = True
					#print "*Instruction writes to memory read by later instrcution"
	

	#if (OPERAND_REGISTER,20) in sink:
	#	print "**** *** ** "+str(ins)
		
	if isTainted:
		TAINTED_INSN.append(ins)

	#print "****"
	#printHexTuple(sink)
	#print "****"

	
	return sink


def analyzeBB(sink,bb,mrw_in_bb):
	for i in range(len(bb)-1,-1,-1):
		ins = bb[i]
		mrw = []
		for k in range(len(mrw_in_bb)-1,-1,-1):
			if mrw_in_bb[k][4] == ins.address:
				mrw.append(mrw_in_bb[k])
		sink = sliceIns(sink, ins, mrw)

	return sink
	# analyze 
#analyze single js statement memory operations.
def analyzeJS(file,sink):
	o = JS_Bin(file)
	rw_list = o.get_rw_list()
	mrw_in_bb =[]
	AllMemOp = False
	new_sink_insn_eip = 0
	AllMemOp = isAllMemOp(sink)

	for i in range(len(rw_list)-1,-1,-1):
		v = rw_list[i]
		#print i
		if AllMemOp: # if all the sink belongs to memory operations, we just search the memory write operation to find the insn write to this location
			if v[3] == 2: # check if this mem_write operates on the mem_read in sink.
				union = isInSink(sink, OPERAND_ABSOLUTE_ADDRESS,v[0],v[1],v[2])
				if len(union) != 0:
					#print "FOUND NEW INSN write to  memory read by later instruction"
					
					sink.difference_update(union)
					AllMemOp = False
					new_sink_insn_eip = v[4]
					#break

		if v[3] == 3 and not AllMemOp:
			#print "\n*****BB"+str(hex(v[4]))+"***** %d\n\n\n"%(i)
			#write2file(v[4],v[2])
			#l = getInsList(BB_CODE_LOC+str(hex(v[4]))[2:]+".bin",v[4])
			l = list(readInsn(MEM_DUMP_LOC,v[4],v[2]))
				

			
			if new_sink_insn_eip != 0: # there is new insn treated as new sink.
				
				while l[-1].address != new_sink_insn_eip:
					l.pop()
				new_sink_insn_eip = 0
				#print str(l[-1])
				
				sink.update(getSinkFromIns(l[-1], mrw_in_bb))
				#printHexTuple(sink)
				#break
				AllMemOp = isAllMemOp(sink)
				#print "NEW SINK "
				#printHexTuple(sink)
				#print str(l[-1].address)+" "+ str(new_sink_insn_eip)+ " "+str(len(l))
				#break 
			sink = analyzeBB(sink, l,mrw_in_bb)
			if isAllMemOp(sink):
				#print "sink all belongs to mem operations"
				AllMemOp = True
				new_sink_insn_eip = 0
				#break
			#else:
				#print " still have register sink "+ str(new_sink_insn_eip)
				#printHexTuple(sink)
			mrw_in_bb = []
			#print "BB"
			#printHexTuple(sink)

			#break
			#printHexTuple(sink)
		else:
			mrw_in_bb.append(v)
	del o
	del rw_list
	#printHexTuple(sink)
	return sink


def clear_stack(sink,cur_esp, max_esp):
	#os.system("echo clear stack> e.txt")
	b = Set()
	for v in sink:
		if v[0] == OPERAND_ABSOLUTE_ADDRESS:
			if v[1] >= max_esp and v[1] < cur_esp:
				b.add(v)

	sink.difference_update(b)
	return sink
def isInCodeModule(eip):
	for v in CODE_MODULE_LIST:
		if eip >= v[0] and eip <= v[0] +v[1]:
			return True
	if eip > 0x50000000:
		return True
	return False

def clear_sink(sink):
	b = Set()
	for v in sink:
		if v[0] == OPERAND_REGISTER:
			b.add(v)
		elif v[0] == OPERAND_ABSOLUTE_ADDRESS:
			if isInCodeModule(v[1]):
				b.add(v)
	sink.difference_update(b)
	
	return sink
# split register sink into 4 bytes sink

def getSinkFromRegister(index,taintedByteIndex):
	sink = Set()
	if index >= Registers.index("EAX") and index <= Registers.index("EDI"):# 4 bytes register
		#print "HI"
		for i in taintedByteIndex:
			sink.add((OPERAND_REGISTER,index,i))	
	elif index >= Registers.index("AX") and index <= Registers.index("DI"): # 2 bytes register
		#print "Two bytes register"
		regindex = Registers.index("E"+Registers[index])
		if 1 in taintedByteIndex:
			sink.add((OPERAND_REGISTER,regindex, 1))
		if 0 in taintedByteIndex:
			sink.add((OPERAND_REGISTER,regindex, 0))
	elif index >= Registers.index("AL") and index <= Registers.index("BL"): # 1 bytes register low byte
		#print "One bytes register low byte"
		regindex = Registers.index("E"+Registers[index][0]+"X")
		if 0 in taintedByteIndex:
			sink.add((OPERAND_REGISTER, regindex, 0))
	elif index >= Registers.index("AH") and index <= Registers.index("BH"): # 1 byte register Hight byte
		#print "one byte reg hight byte"
		regindex = Registers.index("E"+Registers[index][0]+"X")
		if 1 in taintedByteIndex:
			sink.add((OPERAND_REGISTER, regindex, 1))
	return sink
#get sink list for a memory read/write operations
# split it into byte level
def getSinkFromMemory(v,taintedByteIndex):
	#print str(hex(v[0]))+"  "+str(hex(v[1]))+" "+str(hex(v[2]))
	sink = Set()
	if v[1] == 0:
		return sink
	for i in taintedByteIndex:
		#print hex((v[1]>>i*8)& 0xFF )
		#if i< v[2]:
		sink.add((OPERAND_ABSOLUTE_ADDRESS,v[0]+i,(v[1]>>i*8)& 0xFF))
	return sink

def isInSink(sink,type,v1,v2,v3):
	s = Set()
	if type == OPERAND_REGISTER:
		s1 = getSinkFromRegister(v1,[0,1,2,3])
		s = s1.intersection(sink)
	elif type == OPERAND_ABSOLUTE_ADDRESS:
		s1 = getSinkFromMemory([v1,v2,v3],[0,1,2,3])
		s = s1.intersection(sink)
	return s	




#rw: 1, mem read 2, mem write 3, ignore mem location operation
#taintedByteIndex : spcify which byte is considered as tainted byte and should be
#included into new sink
def getSinkFromOperand(oper,eip,mrw,rw,taintedByteIndex):
	sink = Set()
	if isInWhiteList(eip):
		return sink
	type = oper.type
	if type == OPERAND_REGISTER and oper.index not in {20,21}: # register
		sink.update(getSinkFromRegister(oper.index,taintedByteIndex))
	elif type == OPERAND_MEMORY:
		if oper.base != None and oper.base not in {20,21}:# ESP =20 EBP 21
			sink.update(getSinkFromRegister(oper.base,[0,1,2,3]))
		if oper.index != None and oper.index not in { 20, 21}:# ESP = 20 EBP 21
			sink.update(getSinkFromRegister(oper.index,[0,1,2,3]))
		if rw == 3: # only care about register ,ignore memory location
			return sink
		if oper.size/8 ==1:
			taintedByteIndex = [0]
		elif oper.size/8 ==2:
			taintedByteIndex =[0,1]
		elif oper.size/8 == 3:
			taintedByteIndex = [0,1,2]
		elif oper.size/8 ==4:
			taintedByteIndex = [0,1,2,3]

		for v in mrw:
			if v[3] == rw:
				sink.update(getSinkFromMemory(v,taintedByteIndex))
	return sink

def getSinkFromIns(ins, mrw_in_bb):
	#print "geting sink from INSN " + Mnemonics[ins.opcode]
	sink_list = Set()
	if isInWhiteList(ins.address):
		return sink_list
	dest_oper = None
	operands = ins.operands
	mrw = []
	if Mnemonics[ins.opcode] in {"MOVS"}:
		return sink_list
	# get the memory operation for this instruction
	for k in range(len(mrw_in_bb)-1, -1,-1):
		if mrw_in_bb[k][4] == ins.address:
			mrw.append(mrw_in_bb[k])
	sink_list.update(getSinkFromOperand(operands[0], ins.address, mrw, 1,[0,1,2,3]))
	if len(operands) >1:
		sink_list.update(getSinkFromOperand(operands[1], ins.address, mrw, 1,[0,1,2,3]))
	
	return sink_list

#if type is memory access, value for vaddr, value2 for read/write value
def setSink(type, value,value2):
	sink =Set()
	if type == OPERAND_REGISTER:
		sink.update(getSinkFromRegister(value,[0,1,2,3]))
	elif type == OPERAND_ABSOLUTE_ADDRESS:
		sink.update(getSinkFromMemory([value,value2,4],[0,1,2,3]))
	return sink


def isAllMemOp(sink):
	for e in sink:
		if e[0] != OPERAND_ABSOLUTE_ADDRESS:
			return False
	return True

def printHexTuple(tuple_list):
	tuple_list =sorted(tuple_list)
	for t in tuple_list:
		if t[0] == OPERAND_ABSOLUTE_ADDRESS:
			print t[0]+" "+ str(hex(t[1])) +" "+ str(hex(t[2]))
		elif t[0] == OPERAND_REGISTER:
			print t[0]+" "+ Registers[t[1]] + " "+str(t[1]) +" " +str(hex(t[2]))
	#os.sys.exit()
def getStringTuple(tuple_list):
	tuple_list =sorted(tuple_list)
	strs = ""
	for t in tuple_list:
		if t[0] == OPERAND_ABSOLUTE_ADDRESS:
			strs = strs+ t[0]+" "+ str(hex(t[1])) +" "+ str(hex(t[2]))+"\n"
		elif t[0] == OPERAND_REGISTER:
			strs = strs + t[0]+" "+ Registers[t[1]] + " "+str(t[1]) +" " +str(hex(t[2]))+"\n"
	return strs


def dumpCode(rw_list):
	print "dump code out"
	bblist = []
	for v in rw_list:
		if v[3] == 3: # block begin
			bblist.append((v[4],v[2]))
	sorted(bblist)
	print len(bblist)
	a = bblist[0][0]
	b= bblist[len(bblist)-1][0] +bblist[len(bblist)-1][1]
	
	print hex(b-a)
	write2file(a,b-a)
def analyzeCVE(log_dir, sink):
	global MEM_DUMP_LOC
	global TAINTED_INSN
	MEM_DUMP_LOC = log_dir+"virtualmemory.bin"
	count = -1
	print "Setting Start Sink...."
	printHexTuple(sink)
	for root,subfolder,files in os.walk(log_dir):
		for f in files:
			if ".mem" in f:
				count = count +1
	
	for i in range(count, -1 , -1):
		print "***** Analyzing "+str(i) + ".mem********"
		#if i >5038 and i < 9180:
		#	continue
		js_loc = log_dir+str(i)+".mem"
		sink = analyzeJS(js_loc,sink)
		#printHexTuple(sink)
		sink = clear_sink(sink)
		
		#print "CLEAR "
		#printHexTuple(sink)
		

		#print "\n<<<Result For JS %d>>\n"%(i)
		#print "SINK"
		#printHexTuple(sink)
		#print "\nTAINTED INSN"
		strs = ""
		strs = getStringTuple(sink)
		#print strs
		for e in TAINTED_INSN:
			strs = strs+str(hex(e.address))+" "+str(e)+"\n"
		
		if len(TAINTED_INSN)>0:
			os.system("echo '"+strs +"'>> results.txt")
			os.system("echo "+str(i)+".mem>>results.txt")
			os.system("echo "+str(i)+".mem>>result_mem.txt")
		TAINTED_INSN =[]

		if len(sink) ==0:
			print "Backward Analysis done"
			break
		gc.collect()
		#if i == 880:
		#	break

#print last instruction
def test0(file):
	o = JS_Bin(file)
	rw_list = o.get_rw_list()
	v = []
	for i in range(len(rw_list)-1,-1,-1):
		v = rw_list[i]
		if v[3] == 3: #block begin
			print str(hex(v[4]))+"   "+str(hex(v[2]))
			l = readInsn(MEM_DUMP_LOC,v[4],v[2])
			for ins in l:
				print str(hex(ins.address))+" "+str(ins)
			break
		if v[3] == 2:#mem write
			print "EIP "+str(hex(v[4]))+" Write " +str(hex(v[0]))+" "+str(hex(v[1])) 
		elif v[3] == 1:#mem read
			print "EIP "+str(hex(v[4]))+" Read "+ str(hex(v[0]))+" "+str(hex(v[1]))


def test():
	o = JS_Bin("./test/cve20100806/898.mem")
	rw_list = o.get_rw_list()
	for e in rw_list:
		if e[3] == 3:
			write2file(e[4],e[2])
			print hex(e[4])
			print hex(e[2])
		
def test1():
	l = getInsList("/home/smarabbit/work/decaf/trunk/i386-softmmu/1000566b.bin", 0x1000566b)
	print len(BBLIST)
	print l


def test2():
	
	o = JS_Bin("./test/cve20103962/3046.mem")
	rw_list = o.get_rw_list()
	mrw_in_bb =[]
	sink = setSink(OPERAND_REGISTER, Registers.index("EAX"), None) 
	AllMemOp = False
	new_sink_insn_eip = 0
	
	for i in range(len(rw_list)-1,-1,-1):
		v = rw_list[i]

		if AllMemOp: # if all the sink belongs to memory operations, we just search the memory write operation to find the insn write to this location
			if v[3] == 2: # check if this mem_write operates on the mem_read in sink.
				if (OPERAND_ABSOLUTE_ADDRESS, v[0],v[1] ) in sink:
					#print "FOUND NEW INSN write to  memory read by later instruction"
					AllMemOp = False
					sink.remove((OPERAND_ABSOLUTE_ADDRESS, v[0],v[1]))
					new_sink_insn_eip = v[4]
					#break

		if v[3] == 3 and not AllMemOp:
			#print "\n*****BB"+str(hex(v[4]))+"*****\n\n\n"
			#write2file(v[4],v[2])
			#l = getInsList(BB_CODE_LOC+str(hex(v[4]))[2:]+".bin",v[4])
			l = None
			if BBLIST.has_key(v[4]):
				l = BBLIST[v[4]]
			else:
				l = readInsn(MEM_DUMP_LOC,v[4],v[2])
			if new_sink_insn_eip != 0: # there is new insn treated as new sink.
				while l[-1].address != new_sink_insn_eip:
					#print str(l[-1].address)+"  hi "+ str(len(l)) + " "+ str(new_sink_insn_eip)
					l.pop()
				new_sink_insn_eip = 0
				
				sink.update(getSinkFromIns(l[-1], mrw_in_bb))
				#print "NEW SINK "
				#printHexTuple(sink)
				#print str(l[-1].address)+" "+ str(new_sink_insn_eip)+ " "+str(len(l))
				

			sink = analyzeBB(sink, l,mrw_in_bb)
			if isAllMemOp(sink):
				#print "sink all belongs to mem operations"
				AllMemOp = True
				new_sink_insn_eip = 0
				#break
			#else:
				#print " still have register sink "+ str(new_sink_insn_eip)
				#printHexTuple(sink)
			mrw_in_bb = []
			#break
		else:
			mrw_in_bb.append(v)
	for e in TAINTED_INSN:
		print str(e)
	printHexTuple(sink)
def test3():
	print "test 3"
	log_dir = "/home/smarabbit/work/decaf/plugins/browserstub/utils/test/cve20100806/"
	#log_dir = "/home/smarabbit/work/decaf/plugins/browserstub/utils/test/cve20103962/"
	global MEM_DUMP_LOC
	global TAINTED_INSN
	MEM_DUMP_LOC = log_dir+"virtualmemory.bin"
	count = -1
	sink = setSink(OPERAND_REGISTER, Registers.index("ECX"), None) 
	print "Setting Start Sink...."
	printHexTuple(sink)
	for root,subfolder,files in os.walk(log_dir):
		for f in files:
			if ".mem" in f:
				count = count +1
	
	for i in range(count, -1 , -1):
		print "***** Analyzing "+str(i) + ".mem********"
		js_loc = log_dir+str(i)+".mem"
		sink = analyzeJS(js_loc,sink)
		sink = clear_sink(sink)
		

		#print "\n<<<Result For JS %d>>\n"%(i)
		#print "SINK"
		#printHexTuple(sink)
		#print "\nTAINTED INSN"
		strs = ""
		strs = getStringTuple(sink)
		#print strs
		for e in TAINTED_INSN:
			strs = strs+str(hex(e.address))+" "+str(e)+"\n"
		
		if len(TAINTED_INSN)>0:
			os.system("echo '"+strs +"'>> results.txt")
			os.system("echo "+str(i)+".mem>>results.txt")
			os.system("echo "+str(i)+".mem>>result_mem.txt")
		TAINTED_INSN =[]

		if len(sink) ==0:
			print "Backward Analysis done"
			break
		#if i == 880:
		#	break
		
		
def test4():
	#dump code test
	o = JS_Bin("./test/cve20100806/898.mem")
	rw_list = o.get_rw_list()
	dumpCode(rw_list)
#test read code from dumped virutal memory directly.
def test5():
	filepath = "/home/smarabbit/work/decaf/trunk/i386-softmmu/virtualmemory.bin"
	l = readInsn(filepath, 0x7dcc8061,0x19)
	for e in l:
		print str(e)
def test6():
	#sink = getSinkFromRegister(Registers.index("EBP"))
	sink = getSinkFromMemory([0x7dcc8061,0x34383940,4],[0,1,2,3])
	print sink

	s = Set()
	s.add(2)
	c = Set()
	c.add(3)
	c.update(s)
	print c
def test7():
	#sink = getSinkFromMemory([0x3b1ff90,0x0021adb0,4],[0,1,2,3])
	sink = setSink(OPERAND_REGISTER,Registers.index("ECX"),None)
	printHexTuple(sink)
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/cve20084844/virtualmemory.bin"
	analyzeJS("/media/1t1/hu/test/cve20084844/584.mem",sink)
	print "new sink"
	printHexTuple(sink)
	for i in TAINTED_INSN:
		print str(i)



def test_getSinkFromMemory(loc,value,taintedByteIndex):
	sink = Set()
	for i in taintedByteIndex:
		sink.add((OPERAND_ABSOLUTE_ADDRESS,loc+i,(value>>i*8)& 0xFF))
	return sink
def test_cve20100806():
#get last insn
	test0("./test/cve20100806/898.mem")
	log_dir = "/home/smarabbit/work/decaf/plugins/browserstub/utils/test/cve20100806/"
	sink = setSink(OPERAND_REGISTER, Registers.index("ECX"), None) #jump ecx
	analyzeCVE(log_dir,sink)

def test_cve20103962():
	#get last ins
	test0("./test/cve20103962/3048.mem")
	log_dir = "/home/smarabbit/work/decaf/plugins/browserstub/utils/test/cve20103962/"
	sink = setSink(OPERAND_REGISTER, Registers.index("EAX"), None)
	analyzeCVE(log_dir,sink)

def test_cve20100249():
	#get last ins
	#test0("./test/cve20100249/9189.mem")
	'''
	EIP 0x7dc98c85 Write 0x13e358 0x7dc98c88
	EIP 0x7dc98c85 Read 0xd0c0d40 0xc0d0c0d
	EIP 0x7dc98c83 Read 0xc0d0c0d 0xd0c0d0c
	0x7dc98c83   0x5
	0x7dc98c83L MOV EAX, [ECX]
	0x7dc98c85L CALL DWORD [EAX+0x34]


	'''
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t2/hu/test/cve20100249/virtualmemory.bin"

	log_dir = "/media/1t2/hu/test/cve20100249/"
	#sink = test_getSinkFromMemory(0xd0c0d40,0xc0d0c0d,[0,1,2,3])
	sink = setSink(OPERAND_REGISTER,Registers.index("EAX"),None)
	#print sink
	printHexTuple(sink)
	analyzeCVE(log_dir,sink)
def test_cve20090075():
	'''

	EIP 0x7e8999cb Write 0x201f6a8 0x7e8999ce
	EIP 0x7e8999cb Read 0xb0b0b0f 0xd0d0d0d
	EIP 0x7e8999ca Write 0x201f6ac 0x3245d60
	EIP 0x7e8999c8 Read 0x3245d60 0xb0b0b0b
	0x7e8999c8   0x6
	0x7e8999c8L MOV ECX, [EAX]
	0x7e8999caL PUSH EAX
	0x7e8999cbL CALL DWORD [ECX+0x4]




	'''
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t2/hu/test/cve20090075/virtualmemory.bin"
	#get last ins
	test0("/media/1t2/hu/test/cve20090075/3684.mem")
	log_dir = "/media/1t2/hu/test/cve20090075/"
	sink = setSink(OPERAND_REGISTER,Registers.index("ECX"),None)
	analyzeCVE(log_dir,sink)
def test_cve20084844():
	global MEM_DUMP_LOC

	MEM_DUMP_LOC = "/media/1t1/hu/test/cve20084844/virtualmemory.bin"

	log_dir = "/media/1t1/hu/test/cve20084844/"
	#test0(log_dir+"584.mem")

	'''
EIP 0x7ea81de0 Write 0x201fc94 0x7ea81de6
EIP 0x7ea81de0 Read 0xa0a0a8e 0xa0a0a0a
EIP 0x7ea81ddf Write 0x201fc98 0xa0a0072
EIP 0x7ea81dde Write 0x201fc9c 0x244fd08
EIP 0x7ea81ddc Read 0xa0a0072 0xa0a0a0a
0x7ea81ddc   0xa
0x7ea81ddcL MOV ECX, [EAX]
0x7ea81ddeL PUSH EDI
0x7ea81ddfL PUSH EAX
0x7ea81de0L CALL DWORD [ECX+0x84]



	'''

	sink = setSink(OPERAND_REGISTER,Registers.index("ECX"),None)
	analyzeCVE(log_dir, sink)



def test_cve20064777():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/cve20064777/virtualmemory.bin"
	log_dir  = "/media/1t1/hu/test/cve20064777/"
	test0(log_dir+"893.mem")

	'''
EIP 0x7dcc8071 Write 0x12c14d0 0x7
EIP 0x7dcc8070 Read 0x13b95c 0x12c14b0
EIP 0x7dcc806d Read 0x7dc434a0 0x11cf6a4a
EIP 0x7dcc806a Read 0x12c14c0 0x7dc43484
EIP 0x7dcc8066 Write 0x13b964 0x12c0e90
EIP 0x7dcc8064 Read 0x12c14bc 0x12c0e90
0x7dcc8061   0x19
0x7dcc8061L ADD EAX, 0xc
0x7dcc8064L MOV ECX, [EAX]
0x7dcc8066L MOV [ESP+0x8], ECX
0x7dcc806aL MOV ECX, [EAX+0x4]
0x7dcc806dL MOV ECX, [ECX+0x1c]
0x7dcc8070L POP EAX
0x7dcc8071L MOV DWORD [EAX+0x20], 0x7
0x7dcc8078L JMP ECX


	'''
	sink = setSink(OPERAND_REGISTER,Registers.index("ECX"),None)
	analyzeCVE(log_dir,sink)

#CFI not work
def test_cve20091136():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/cve20091136/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/cve20091136/"
	#test0(log_dir+"")
def test_mpcve20100806():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/mp/cve20100806/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/mp/cve20100806/"
	test0(log_dir +"897.mem")
	sink = setSink(OPERAND_REGISTER, Registers.index("ECX"), None) #jump ecx
	print datetime.now()
	os.system("echo "+str(datetime.now())+">time.txt")
	analyzeCVE(log_dir,sink)
	os.system("echo "+str(datetime.now())+">>time.txt")

def test_mpcve20103962():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/mp/cve20103962/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/mp/cve20103962/"
	test0(log_dir + "1164.mem")

	sink = setSink(OPERAND_REGISTER, Registers.index("EAX"), None)
	print datetime.now()
	os.system("echo "+str(datetime.now())+">time.txt")
	analyzeCVE(log_dir,sink)
	os.system("echo "+str(datetime.now())+">>time.txt")


def test_mpcve20121889():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/mp/cve20121889/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/mp/cve20121889/"
	'''

EIP 0x7c86402f Write 0x13db44 0x7c864031
EIP 0x7c864029 Write 0x13db48 0x13ddd8
EIP 0x7c864029 Read 0x13dc60 0x13ddd8
0x7c864029   0x8
0x7c864029L PUSH DWORD [EBP-0x150]
0x7c86402fL CALL EBX



	'''
	test0(log_dir+"7251.mem")
	sink = setSink(OPERAND_REGISTER, Registers.index("EBX"),None)
	print datetime.now()
	os.system("echo "+str(datetime.now())+">time.txt")
	analyzeCVE(log_dir,sink)
	os.system("echo "+str(datetime.now())+">>time.txt")
def test_mpcve20133163():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/mp/cve20133163/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/mp/cve20133163/"

	test0(log_dir +"269.mem")
	'''
	EIP 0x6363fcc9 Write 0x316d1b0 0x6363fccb
	EIP 0x6363fcc6 Read 0x5fe10e0 0x77c15ed5
	EIP 0x6363fcc4 Read 0x346dfb0 0x5fe1070
	0x6363fcc4   0x7
	0x6363fcc4L MOV EAX, [ECX]
	0x6363fcc6L MOV EDX, [EAX+0x70]
	0x6363fcc9L CALL EDX



	'''
	sink = setSink(OPERAND_REGISTER, Registers.index("EDX"), None)
	print datetime.now()
	os.system("echo "+str(datetime.now())+">time.txt")
	analyzeCVE(log_dir,sink)
	os.system("echo "+str(datetime.now())+">>time.txt")
def test_mpcve20121876():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/mp/cve20121876/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/mp/cve20121876/"

	#test0(log_dir+"3530.mem")
	'''
	EIP 0x636747c3 Write 0x316f574 0x636747c6
	EIP 0x636747c3 Read 0x7070094 0x374ae388
	EIP 0x636747bf Read 0x5ec9058 0x7070024
	0x636747bf   0x7070024
	0x636747bfL MOV EDX, [EAX]
	0x636747c1L MOV ECX, EAX
	0x636747c3L CALL DWORD [EDX+0x70]
	'''
	sink = setSink(OPERAND_REGISTER, Registers.index("EDX"), None)
	print datetime.now()
	os.system("echo "+str(datetime.now())+">time.txt")
	analyzeCVE(log_dir,sink)
	os.system("echo "+str(datetime.now())+">>time.txt")
def test_mpcve20133897():
	global MEM_DUMP_LOC
	MEM_DUMP_LOC = "/media/1t1/hu/test/mp/cve20133897/virtualmemory.bin"
	log_dir = "/media/1t1/hu/test/mp/cve20133897/"

	test0(log_dir+"4742.mem")

	#set the filter
	global WHITE_LIST
	global CODE_MODULE_LIST
	#WHITE_LIST = []
	#CODE_MODULE_LIST = []
	#NetbeansExtension.dll msdbg2.dll pdm.dll msdbg.dll jscript.dll stub.dll
	WHITE_LIST = [(0x10000000,0x00016000),(0x3f0e0000,0x00042000),(0x3f320000,0x00058000),(0x4aa00000,0x00015000),(0x63380000,0x000b4000),(0x6d040000,0x0001a000)]

	CODE_MODULE_LIST = [(0x00400000,0x0009c000),(0x00930000,0x00009000),(0x00970000,0x00006000),(0x00e30000,0x002c5000),\
	(0x01120000,0x00a91000),(0x022c0000,0x0002a000),(0x02e30000,0x00040000),(0x032d0000,0x000bf000),(0x033c0000,0x00029000),\
	(0x035a0000,0x00094000),(0x10000000,0x00016000),(0x1a400000,0x00132000),(0x3f0e0000,0x00042000),(0x3f320000,0x00058000),\
	(0x47060000,0x00021000),(0x4aa00000,0x00015000),(0x5ad70000,0x00038000),(0x5b860000,0x00055000),(0x5d090000,0x0009a000),\
	(0x5dca0000,0x001e8000),(0x62c70000,0x00019000),(0x63000000,0x000e6000),(0x63380000,0x000b4000),(0x63580000,0x005ac000),\
	(0x662b0000,0x00058000),(0x68000000,0x00036000),(0x6cd00000,0x00024000),(0x6d040000,0x0001a000),(0x6d1d0000,0x0005c000),\
	(0x6e1e0000,0x0002e000),(0x6e5c0000,0x00074000),(0x71a50000,0x0003f000),(0x71a90000,0x00008000),(0x71aa0000,0x00008000),\
	(0x71ab0000,0x00017000),(0x71d40000,0x0001b000),(0x722b0000,0x00005000),(0x72ea0000,0x0006f000),(0x746f0000,0x0002a000),\
	(0x74720000,0x0004c000),(0x74980000,0x00113000),(0x74c80000,0x0002c000),(0x74d90000,0x0006b000),(0x755c0000,0x0002e000),\
	(0x75cf0000,0x00091000),(0x76080000,0x00065000),(0x76380000,0x00005000),(0x76390000,0x0001d000),(0x763b0000,0x00049000),\
	(0x76600000,0x0001d000),(0x769c0000,0x000b4000),(0x76b40000,0x0002d000),(0x76bf0000,0x0000b000),(0x76d60000,0x00019000),\
	(0x76e80000,0x0000e000),(0x76e90000,0x00012000),(0x76eb0000,0x0002f000),(0x76ee0000,0x0003c000),(0x76f20000,0x00027000),\
	(0x76fc0000,0x00006000),(0x76fd0000,0x0007f000),(0x77050000,0x000c5000),(0x77120000,0x0008b000),(0x773d0000,0x00103000),\
	(0x774e0000,0x0013d000),(0x77920000,0x000f3000),(0x77a20000,0x00054000),(0x77a80000,0x00095000),(0x77b20000,0x00012000),\
	(0x77b40000,0x00022000),(0x77c00000,0x00008000),(0x77c10000,0x00058000),(0x77c70000,0x00024000),(0x77dd0000,0x0009b000),\
	(0x77e70000,0x00092000),(0x77f10000,0x00049000),(0x77f60000,0x00076000),(0x77fe0000,0x00011000),(0x78050000,0x00069000),\
	(0x78a60000,0x00026000),(0x78aa0000,0x000bf000),(0x7c800000,0x000f6000),(0x7c900000,0x000af000),(0x7c9c0000,0x00817000),\
	(0x7e410000,0x00091000),(0x7e720000,0x000b0000)]


	sink = setSink(OPERAND_REGISTER, Registers.index("EAX"),None)

	print datetime.now()
	os.system("echo "+str(datetime.now())+">time.txt")
	analyzeCVE(log_dir,sink)
	os.system("echo "+str(datetime.now())+">>time.txt")	
	
test_mpcve20133897()
#test_mpcve20121876()
#test_mpcve20133163()
#test_mpcve20121889()
#test_mpcve20103962()
#test_mpcve20100806()
#test_cve20064777()
#test_cve20090075()
#test_cve20100249()
#test_cve20084844()
#test0("./test/cve20100249/9626.mem")
#get the last instruction
#test0("./test/cve20100806/898.mem")

#test0("./test/cve20103962/3048.mem")
#for cve-201--0806
#test3()
#for cve-2010-3962
#test2()

#test read code from dumped virtual memory directly
#test5()

#test byte level backward slicing.

#test6()
#test7()
