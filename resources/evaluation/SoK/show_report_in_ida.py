import json
import pathlib
import logging
import binascii
import dataclasses
from typing import List
from dataclasses import dataclass

import ida_gdl
import ida_nalt
import ida_name
import ida_bytes
import ida_lines
import ida_funcs
import ida_graph
import ida_kernwin
import idautils

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("layout")


@dataclass
class Layout:
    functions: set[int]
    basic_blocks: set[int]
    instructions: set[int]


def load_layout_report(path: pathlib.Path) -> Layout:
    layout = Layout(set(), set(), set())
    
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("function"):
            _, _, addr = line.partition(": ")
            addr = int(addr, 16)
            layout.functions.add(addr)

        elif line.startswith("basic block"):
            _, _, addr = line.partition(": ")
            addr = int(addr, 16)
            layout.basic_blocks.add(addr)

        elif line.startswith("instruction"):
            _, _, addr = line.partition(": ")
            addr = int(addr, 16)
            layout.instructions.add(addr)

        else:
            logger.warning("unknown line: %s", line)
            continue

    return layout


def load_current_report() -> Layout:
    layout = Layout(set(), set(), set())

    for f in idautils.Functions():
        layout.functions.add(f)

        flowchart = ida_gdl.FlowChart(ida_funcs.get_func(f), flags=ida_gdl.FC_NOEXT)
        if not flowchart or flowchart.size == 0:
            continue

        for bb in flowchart:
            layout.basic_blocks.add(bb.start_ea)

            for head in idautils.Heads(bb.start_ea, bb.end_ea):
                layout.instructions.add(head)

    return layout


def do_show_report():
    path = ida_kernwin.ask_file(False, "*.txt", "path to layout report file")
    if not path:
        return

    p = pathlib.Path(path)
    if not p.exists():
        return

    lancelot_layout = load_layout_report(p)
    ida_layout = load_current_report()

    for f in sorted(ida_layout.functions - lancelot_layout.functions):
        logger.warning("missing function: %s", hex(f))

    # these are often tail calls
    #for f in sorted(lancelot_layout.functions - ida_layout.functions):
    #    logger.warning("extra function: %s", hex(f))


def main():
    do_show_report()


if __name__ == "__main__":
    main()
















