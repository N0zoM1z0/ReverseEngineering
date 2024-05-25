from unicorn import *
from unicorn.arm_const import *
import struct
from pwn import *
from capstone import *

def read(name):
    with open(name,"rb") as f:
        return f.read()

md = Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN)
mu = Uc(UC_ARCH_ARM,UC_MODE_LITTLE_ENDIAN) # ARM32 小端序

BASE_ADDR = 0x10000
STACK_ADDR = 0x400000
STACK_SIZE = 1024*1024

mu.mem_map(BASE_ADDR,1024*1024)
mu.mem_map(STACK_ADDR,STACK_SIZE)
mu.mem_write(BASE_ADDR,read("./task4"))

mu.reg_write(UC_ARM_REG_SP,STACK_ADDR + STACK_SIZE - 1)

CCC_ENTRY = 0X104D0
CCC_END = 0X10580
stack = [] # 保留regs
dp = {} # 记忆化

def hook_code(mu:Uc,address,size,user_data):
    # machine_code = mu.mem_read(address,size)
    # for code in md.disasm(machine_code,address):
	#     print("     0x%x:\t%s\t%s" % (code.address, code.mnemonic, code.op_str))
    if address == CCC_ENTRY:
        r0 = mu.reg_read(UC_ARM_REG_R0)
        reg0 = r0
        if reg0 in dp:
            ret_val = dp[reg0]    
            mu.reg_write(UC_ARM_REG_R0,ret_val) # 返回值也是R0
            mu.reg_write(UC_ARM_REG_PC,0x000105BC) # 改变PC-> ret 还是用main的ret
        else:
            stack.append(reg0)
    
    elif address == CCC_END:
        reg0 = stack.pop()
        ret_val = mu.reg_read(UC_ARM_REG_R0)
        dp[reg0] = ret_val
        

mu.hook_add(UC_HOOK_CODE,hook_code)
mu.emu_start(0x10584,0x00010594) 
print(f"[+] The answer is: {mu.reg_read(UC_ARM_REG_R3)}")