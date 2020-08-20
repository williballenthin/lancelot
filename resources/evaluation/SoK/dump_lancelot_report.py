import sys
import lancelot

with open(sys.argv[1], "rb") as f:
    ws = lancelot.from_bytes(f.read())

for f in ws.get_functions():
    print("function: " + hex(f))

    try:
        cfg = ws.build_cfg(f)
    except:
        continue
    else:
        for bb in cfg.basic_blocks.values():
            print("basic block: " + hex(bb.address))

            va = bb.address
            while va < bb.address + bb.length:
                try:
                    insn = ws.read_insn(va)
                except ValueError:
                    break
                print("instruction: " + hex(insn.address))
                va += insn.length
