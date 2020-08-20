import sys
import viv_utils

vw = viv_utils.getWorkspace(sys.argv[1])
for f in vw.getFunctions():
    f = viv_utils.Function(vw, f)
    print("function: " + hex(f.va))

    for bb in f.basic_blocks:
        print("basic block: " + hex(bb.va))

        for insn in bb.instructions:
            print("instruction: " + hex(insn.va))
