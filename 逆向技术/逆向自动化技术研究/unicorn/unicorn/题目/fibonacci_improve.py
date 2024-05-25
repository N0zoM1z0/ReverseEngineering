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

FIBONACCI_ENTRY = 0x400670
FIBONACCI_END = [0x4006F1,0x400709] # 两个retn处
stack = [] # 保存值的栈 (由于是递归调用 所以需要用栈来实现寄存器的存储)
dp = {} # 记忆化

def hook_code(mu:Uc,address,size,user_data):
    # print("[+] Tracing instruction at 0x%x, instruction size = 0x%x" % (address,size))
    skips = [0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F]
    if address in skips:
        mu.reg_write(UC_X86_REG_RIP,address + size)
        
    elif address == 0x400560: # 跳过__IO_putc
        c = mu.reg_read(UC_X86_REG_RDI) # movsx   edi, dil        ; c
        print(chr(c&0xFF),end='')
        mu.reg_write(UC_X86_REG_RIP,address + size)

    elif address == FIBONACCI_ENTRY:
        arg0 = mu.reg_read(UC_X86_REG_RDI) # int a1
        # 注意 第二个是寄存器间接寻址 且a2的值是会改变的(按址传递)
        r_rsi = mu.reg_read(UC_X86_REG_RSI)
        arg1 = u32(mu.mem_read(r_rsi,4)) # _DWORD *a2

        if (arg0,arg1) in dp: # 妙！ 以元组存dp
            (ret_rax,ret_ref) = dp[(arg0,arg1)] 
            mu.reg_write(UC_X86_REG_RAX,ret_rax) # 第一个参数赋值给RAX
            mu.mem_write(r_rsi,p32(ret_ref)) # 第二个参数写入rsi指向的地址中 mem_write
            # 设置返回点(rip)
            mu.reg_write(UC_X86_REG_RIP,0x400582) # 这里用的是main的ret指令
            # 为什么不能用fibonacci函数的 因为这个函数在hook中 所以不能跳到函数本身的ret指令
        else:
            stack.append((arg0,arg1,r_rsi)) # 不在dp数组就入栈
    # 遇到fibonacci函数的出口 从栈顶取数据建立映射
    elif address in FIBONACCI_END:
        (arg0,arg1,r_rsi) = stack.pop()
        ret_rax = mu.reg_read(UC_X86_REG_RAX)
        ret_ref = u32(mu.mem_read(r_rsi,4))
        dp[(arg0,arg1)] = (ret_rax,ret_ref)


mu.hook_add(UC_HOOK_CODE,hook_code)
# 模拟执行的开始地址和结束地址 main和IO_PUTC
mu.emu_start(0x4004E0,0x400575)
print("\n[+] Done!")