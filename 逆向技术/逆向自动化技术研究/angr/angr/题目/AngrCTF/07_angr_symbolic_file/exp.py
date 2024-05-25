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

p = Project("./07_angr_symbolic_file")

state = p.factory.entry_state(addr = 0x080488D3)
print(f"[+] esp: {state.regs.esp}")

filename = "OJKSQYDP.txt"
file_size = 0x40
pass1 = BVS('pass1',8*0x40)
sim_file = SimFile(filename,content=pass1,size=file_size)

state.fs.insert(filename,sim_file)

sim = p.factory.simgr(state)

sim.explore(find = good,avoid = bad)

if sim.found:
    res = sim.found[0]
    pass1 = sim.found[0].solver.eval(pass1,cast_to=bytes)

    print(f"[+] Success! The solution is {pass1}")
