from angr import *
from claripy import *

def good(state):
    stdout_output = state.posix.dumps(1)
    if b'Good Job.' in stdout_output:
        return True
    else: 
        return False
def bad(state):
    stdout_output = state.posix.dumps(1)
    if b'Try again.' in stdout_output:
        return True
    else: 
        return False

p = Project("./09_angr_hooks")

state = p.factory.entry_state(addr = 0x08048625)
print(f"[+] esp: {state.regs.esp}")



sim = p.factory.simgr(state)

check_addr = 0x08048565

sim.explore(find = check_addr)

if sim.found:
    check_state = sim.found[0]
    pass1 = check_state.solver.eval(pass1,cast_to=bytes)
    
    print(f"[+] Success! The solution is {pass1}")
