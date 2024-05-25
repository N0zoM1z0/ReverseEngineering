from unicorn import *
from unicorn.x86_const import *
import struct
from pwn import *

# 读取文件内容
def read(name):
    with open(name,"rb") as f:
        return f.read()
    
# 初始化unicorn引擎
# 架构类型 架构说明  x86_64
mu = Uc(UC_ARCH_X86,UC_MODE_64)

# 二进制文件的基址
BASE = 0x400000
# 可以自主分配栈
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

# 映射内存
mu.mem_map(BASE,1024*1024)
mu.mem_map(STACK_ADDR,STACK_SIZE)

# 加载二进制文件到准备好的基址
mu.mem_write(BASE,read("./fibonacci"))

# 设置rsp指向我们自己分配的栈的底部
mu.reg_write(UC_X86_REG_RSP,STACK_ADDR + STACK_SIZE - 1)

# 加hook_code打印指令
# mu:Uc实例句柄  address:指令地址  size:执行的长度   user_data:用户自定义数据(可选传递)

def hook_code(mu:Uc,address,size,user_data):
    # print("[+] Tracing instruction at 0x%x, instruction size = 0x%x" % (address,size))
    skips = [0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F]
    if address in skips:
        mu.reg_write(UC_X86_REG_RIP,address + size)
    elif address == 0x400560: # 跳过__IO_putc
        c = mu.reg_read(UC_X86_REG_RDI) # movsx   edi, dil        ; c
        print(chr(c),end='')
        mu.reg_write(UC_X86_REG_RIP,address + size)

mu.hook_add(UC_HOOK_CODE,hook_code)
# 模拟执行的开始地址和结束地址 main和IO_PUTC
mu.emu_start(0x4004E0,0x400575)