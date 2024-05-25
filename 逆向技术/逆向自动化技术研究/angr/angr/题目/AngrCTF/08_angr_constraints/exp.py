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

p = Project("./08_angr_constraints")

state = p.factory.entry_state(addr = 0x08048625)
print(f"[+] esp: {state.regs.esp}")

buffer_addr = 0x0804A050
pass1 = BVS("pass1",8*16)
state.memory.store(buffer_addr,pass1)

sim = p.factory.simgr(state)

check_addr = 0x08048565

sim.explore(find = check_addr)

if sim.found:
    check_state = sim.found[0]
    enc = "AUPDNNPROEZRJWKB"

    check_param1 = buffer_addr
    check_param2 = 0x10
    
    check_bvs = check_state.memory.load(check_param1,check_param2)
    check_constraint = check_bvs == enc
    check_state.add_constraints(check_constraint)

    pass1 = check_state.solver.eval(pass1,cast_to=bytes)
    
    print(f"[+] Success! The solution is {pass1}")
