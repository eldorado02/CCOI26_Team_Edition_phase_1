import angr
import claripy
import sys

BINARY = "./knight_vault"

def solve():
    proj = angr.Project(BINARY, auto_load_libs=False)

    # 32 printable bytes input (the seal token)
    flag_chars = [claripy.BVS(f"c{i}", 8) for i in range(32)]
    flag = claripy.Concat(*flag_chars)

    # Constraints: printable ASCII
    constraints = []
    for c in flag_chars:
        constraints.append(c >= 0x20)
        constraints.append(c <= 0x7e)

    # Entry state with stdin simulation
    # fgets reads up to 0x100 bytes, terminated by newline
    stdin_content = flag.concat(claripy.BVV(b"\n"))

    state = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name='stdin', content=stdin_content, has_end=False),
        add_options={angr.options.LAZY_SOLVES}
    )

    for c in constraints:
        state.solver.add(c)

    # PIE base is determined by angr automatically
    # Find success ("Vault opened.") — avoid failure ("Vault sealed.")
    base = proj.loader.min_addr
    print(f"[*] Binary loaded at base: {hex(base)}")

    # From the disassembly, relative to the PIE binary:
    # 0x11fc = puts("Vault opened.")  → SUCCESS
    # 0x1226 = puts("Vault sealed.")  → FAILURE
    find_addr  = base + 0x11fc
    avoid_addr = base + 0x1226

    print(f"[*] Find:  {hex(find_addr)}")
    print(f"[*] Avoid: {hex(avoid_addr)}")

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=find_addr, avoid=avoid_addr)

    if simgr.found:
        sol = simgr.found[0]
        result = sol.solver.eval(flag, cast_to=bytes)
        print(f"\n[+] Seal token found: {result.decode('latin-1')}")
        print(f"[+] FLAG: {result.decode('latin-1')}")
        return result
    else:
        print("[-] No solution found.")
        return None

if __name__ == "__main__":
    solve()
