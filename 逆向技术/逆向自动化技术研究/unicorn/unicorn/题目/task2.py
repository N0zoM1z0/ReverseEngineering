from unicorn import *
from unicorn.x86_const import *
from pwn import *
from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_32)

shellcode = b"\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"

mu = Uc(UC_ARCH_X86,UC_MODE_32)

BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu.mem_map(BASE,1024*1024)
mu.mem_map(STACK_ADDR,STACK_SIZE)

mu.mem_write(BASE,shellcode)

# 设置esp指向栈底
mu.reg_write(UC_X86_REG_ESP,STACK_ADDR + STACK_SIZE - 1)

def syscall_2_name(num:int):
    syscalls = {1:"sys_exit",15:"sys_chmod"}
    return syscalls[num]

def hook_code(mu:Uc,address,size,user_data):
    machine_code = mu.mem_read(address,size)
    for code in md.disasm(machine_code,address):
	    print("     0x%x:\t%s\t%s" % (code.address, code.mnemonic, code.op_str))
    # hook int 80
    if machine_code == b"\xcd\x80":
        r_eax = mu.reg_read(UC_X86_REG_EAX) # eax 系统调用号
        r_ebx = mu.reg_read(UC_X86_REG_EBX) # eax 系统调用号
        r_ecx = mu.reg_read(UC_X86_REG_ECX) # eax 系统调用号
        r_edx = mu.reg_read(UC_X86_REG_EDX) # eax 系统调用号

        syscall_name = syscall_2_name(r_eax)
        print(f"[+] intercepted system call: {syscall_name}")
        if syscall_name == "sys_chmod":
            # ebx,ecx
            s = mu.mem_read(r_ebx,20).split(b"\x00")[0]
            print(f"[+] arg0 = {hex(r_ebx)} -> {s}")
            print(f"[+] arg1 =  {oct(r_ecx)}")
        elif syscall_name == "sys_exit":
            print(f"arg0 = {hex(r_ebx)}")
        # 跳过int 80 (恶意代码)
        mu.reg_write(UC_X86_REG_EIP,address + size)

mu.hook_add(UC_HOOK_CODE,hook_code)
mu.emu_start(BASE,BASE+len(shellcode)*8)