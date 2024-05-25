from unicorn import *
from unicorn.x86_const import *
import struct
from pwn import *
from capstone import *

def read(name):
    with open(name,"rb") as f:
        return f.read()

md = Cs(CS_ARCH_X86, CS_MODE_32)
mu = Uc(UC_ARCH_X86,UC_MODE_32)

BASE_ADDR = 0x0
STACK_ADDR = 0x400000
STACK_SIZE = 1024*1024

mu.mem_map(BASE_ADDR,1024*1024)
mu.mem_map(STACK_ADDR,STACK_SIZE)
mu.mem_write(BASE_ADDR,read("./function"))

mu.reg_write(UC_X86_REG_ESP,STACK_ADDR + STACK_SIZE - 1)

def hook_code(mu:Uc,address,size,user_data):
    machine_code = mu.mem_read(address,size)
    for code in md.disasm(machine_code,address):
	    print("     0x%x:\t%s\t%s" % (code.address, code.mnemonic, code.op_str))

    if address == 0x5CA: # call super_function
        STRING_ADDR = BASE_ADDR + 1024 # 随便找个内存写字符串
        mu.mem_write(STRING_ADDR,b"batman\x00")
        
        esp = mu.reg_read(UC_X86_REG_ESP) # 通过esp来定位栈
        mu.mem_write(esp+0,p32(5)) # 第一个参数
        mu.mem_write(esp+4,p32(STRING_ADDR)) # 第二个参数
        """ 
        ---
        arg1    <- esp+4
        ---
        arg0    <- esp    
        """
        pass

mu.hook_add(UC_HOOK_CODE,hook_code)
mu.emu_start(0x5B4,0x5B1) 
ret_val = mu.reg_read(UC_X86_REG_EAX)
print(f"[+] The return value is : {ret_val}")