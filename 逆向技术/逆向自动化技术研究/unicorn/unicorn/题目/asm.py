from unicorn import *
from unicorn.x86_const import *
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)

ADDRESS = 0x2E1000          # 程序加载的地址
INPUT_ADDRESS = 0x2E701D    # 输入的地址
KEY_ADDRESS = 0x2E705C      # 16字节key的地址
with open('./OddCode.exe', 'rb') as file:
    file.seek(0x400)
    X64_CODE = file.read(0x4269)    # 读取代码

ASM = []
 
class Unidbg:
 
    def __init__(self, flag):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # 基址为0x2E1000，分配16MB内存
        mu.mem_map(ADDRESS, 0x1000000)
        mu.mem_write(ADDRESS, X64_CODE)
        mu.mem_write(INPUT_ADDRESS, flag)       # 随便写入一个flag
        mu.mem_write(KEY_ADDRESS, b'\x90\xF0\x70\x7C\x52\x05\x91\x90\xAA\xDA\x8F\xFA\x7B\xBC\x79\x4D')
        # 初始化寄存器，寄存器的状态就是切换到64位模式之前的状态，可以通过动调得到
        mu.reg_write(UC_X86_REG_RAX, 1)
        mu.reg_write(UC_X86_REG_RBX, 0x51902D)
        mu.reg_write(UC_X86_REG_RCX, 0xD86649D8)
        mu.reg_write(UC_X86_REG_RDX, 0x2E701C)
        mu.reg_write(UC_X86_REG_RSI, INPUT_ADDRESS)  # input参数
        mu.reg_write(UC_X86_REG_RDI, KEY_ADDRESS)    # key参数
        mu.reg_write(UC_X86_REG_RBP, 0x6FFBBC)
        mu.reg_write(UC_X86_REG_RSP, 0x6FFBAC)
        mu.reg_write(UC_X86_REG_RIP, 0x2E1010)
        mu.hook_add(UC_HOOK_CODE, self.trace)        # hook代码执行，保存代码块执行轨迹
        self.mu = mu
        self.except_addr = 0
        self.traces = []        # 用来保存代码块执行轨迹
 
    def trace(self, mu:Uc, address, size, data):
        machine_code = mu.mem_read(address,size)
        for code in md.disasm(machine_code,address):
	        ASM.append("     0x%x:\t%s\t%s" % (code.address, code.mnemonic, code.op_str))
        # --过滤花指令--
        if address != self.except_addr:
            self.traces.append(address)
        self.except_addr = address + size
 
    def start(self):
        try:
            self.mu.emu_start(0x2E1010, -1)
        except:
            pass
        print([hex(addr)for addr in self.traces])
 
Unidbg(b'SangFor{00000000000000000000000000000000}').start()
ff = open("./asm.txt","w")
for asm in ASM:
    ff.write(asm + "\n")
ff.close()