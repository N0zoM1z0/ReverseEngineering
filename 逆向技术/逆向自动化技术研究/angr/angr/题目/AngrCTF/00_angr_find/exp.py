from angr import *
from claripy import *

p = Project("./00_angr_find")
state = p.factory.entry_state()
sim = p.factory.simgr(state)

sim.explore(find = 0x804867D)

if sim.found:
    res = sim.found[0]
    res = res.posix.dumps(0)
    print(f"[+] Success! The solution is {res.decode()}")