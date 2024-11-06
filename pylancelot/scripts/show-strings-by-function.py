#!/usr/bin/env python
import sys
import logging
import argparse
from pathlib import Path

import rich
import lancelot
import lancelot.be2utils
from lancelot.be2utils import BinExport2Index
from lancelot.be2utils.binexport2_pb2 import BinExport2

logger = logging.getLogger("inspect-workspace")


def is_vertex_type(vertex: BinExport2.CallGraph.Vertex, type_: BinExport2.CallGraph.Vertex.Type.ValueType) -> bool:
    return vertex.HasField("type") and vertex.type == type_


THUNK_CHAIN_DEPTH_DELTA = 5


def compute_thunks(be2: BinExport2, idx: BinExport2Index) -> dict[int, int]:
    # from thunk address to target function address
    thunks: dict[int, int] = {}

    for addr, vertex_idx in idx.vertex_index_by_address.items():
        vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[vertex_idx]
        if not is_vertex_type(vertex, BinExport2.CallGraph.Vertex.Type.THUNK):
            continue

        curr_vertex_idx: int = vertex_idx
        for _ in range(THUNK_CHAIN_DEPTH_DELTA):
            thunk_callees: list[int] = idx.callees_by_vertex_index[curr_vertex_idx]
            # if this doesn't hold, then it doesn't seem like this is a thunk,
            # because either, len is:
            #    0 and the thunk doesn't point to anything, such as `jmp eax`, or
            #   >1 and the thunk may end up at many functions.

            if not thunk_callees:
                # maybe we have an indirect jump, like `jmp eax`
                # that we can't actually resolve here.
                break

            assert len(thunk_callees) == 1, f"thunk @ {hex(addr)} failed"

            thunked_vertex_idx: int = thunk_callees[0]
            thunked_vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[thunked_vertex_idx]

            if not is_vertex_type(thunked_vertex, BinExport2.CallGraph.Vertex.Type.THUNK):
                assert thunked_vertex.HasField("address")

                thunks[addr] = thunked_vertex.address
                break

            curr_vertex_idx = thunked_vertex_idx

    return thunks


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Show a PE file's strings by function")
    parser.add_argument("input_file", type=Path, help="path to input file")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    args = parser.parse_args(args=argv)

    logging.basicConfig()
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    input_file: Path = args.input_file
    buf: bytes = lancelot.get_binexport2_bytes_from_bytes(input_file.read_bytes())

    be2: BinExport2 = BinExport2()
    be2.ParseFromString(buf)

    idx = lancelot.be2utils.BinExport2Index(be2)
    thunks = compute_thunks(be2, idx)

    for flow_graph_index, flow_graph in enumerate(be2.flow_graph):
        strings: set[str] = set()
        apis: set[str] = set()

        entry_basic_block_index: int = flow_graph.entry_basic_block_index
        flow_graph_address: int = idx.get_basic_block_address(entry_basic_block_index)

        for basic_block_index in flow_graph.basic_block_index:
            basic_block: BinExport2.BasicBlock = be2.basic_block[basic_block_index]

            for instruction_index, instruction, instruction_address in idx.basic_block_instructions(basic_block):

                if instruction_index in idx.string_reference_index_by_source_instruction_index:
                    for string_reference_index in idx.string_reference_index_by_source_instruction_index[
                        instruction_index
                    ]:
                        string_reference: BinExport2.Reference = be2.string_reference[string_reference_index]
                        string_index: int = string_reference.string_table_index
                        string: str = be2.string_table[string_index]
                        strings.add(string)

                for addr in instruction.call_target:
                    addr = thunks.get(addr, addr)

                    if addr not in idx.vertex_index_by_address:
                        # disassembler did not define function at address
                        logger.debug("0x%x is not a vertex", addr)
                        continue

                    vertex_idx: int = idx.vertex_index_by_address[addr]
                    vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[vertex_idx]

                    if not is_vertex_type(vertex, BinExport2.CallGraph.Vertex.Type.IMPORTED):
                        continue

                    if not vertex.HasField("mangled_name"):
                        logger.debug("vertex %d does not have mangled_name", vertex_idx)
                        continue

                    api_name: str = vertex.mangled_name

                    if vertex.HasField("library_index"):
                        library = be2.library[vertex.library_index]
                        api_name = library.name + "!" + api_name

                    apis.add(api_name)

        vertex_index = idx.vertex_index_by_address[flow_graph_address]
        name = idx.get_function_name_by_vertex(vertex_index)

        if strings or apis:
            rich.print(f"[yellow]{name}[/] [grey37]@ {hex(flow_graph_address)}:[/]")

            for string in sorted(strings):
                print(f'  - "{string}"')

            for api in sorted(apis):
                if "!" in api:
                    dll, _, name = api.partition("!")
                    rich.print(f"  - [grey37]{dll}![/]{name}")
                else:
                    rich.print(f"  - {api}")
        else:
            rich.print(f"[yellow]{name}[/] [grey37]@ {hex(flow_graph_address)}: (none)[/]")


if __name__ == "__main__":
    sys.exit(main())
