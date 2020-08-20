import idaapi
import idautils

lines = []

for ea in idautils.Functions(0x0, 0xFFFFFFFFFFFFFFFF):
    lines.append("function: %s" % hex(ea))
    f = idaapi.get_func(ea)

    for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
        lines.append("basic block: %s" % hex(bb.start_ea))

        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            insn = idautils.DecodeInstruction(head)
            if not insn:
                continue
            lines.append("instruction: %s" % hex(head))

print("\n".join(lines))

import ida_pro
ida_pro.qexit(0)
