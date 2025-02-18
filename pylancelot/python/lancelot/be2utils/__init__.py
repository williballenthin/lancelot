"""
Proto files generated via protobuf v24.4:

    protoc --python_out=. --mypy_out=. binexport2.proto

from BinExport2 at 6916731d5f6693c4a4f0a052501fd3bd92cfd08b
https://github.com/google/binexport/blob/6916731/binexport2.proto
"""

import io
import logging
from collections.abc import Iterator
from collections import defaultdict
from dataclasses import dataclass

from pefile import PE
from elftools.elf.elffile import ELFFile
from lancelot.be2utils.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def is_vertex_type(vertex: BinExport2.CallGraph.Vertex, type_: BinExport2.CallGraph.Vertex.Type.ValueType) -> bool:
    return vertex.HasField("type") and vertex.type == type_


def is_thunk_vertex(vertex: BinExport2.CallGraph.Vertex) -> bool:
    return is_vertex_type(vertex, BinExport2.CallGraph.Vertex.Type.THUNK)


THUNK_CHAIN_DEPTH_DELTA = 5


class BinExport2Index:
    def __init__(self, be2: BinExport2):
        self.be2: BinExport2 = be2

        self.callers_by_vertex_index: dict[int, list[int]] = defaultdict(list)
        self.callees_by_vertex_index: dict[int, list[int]] = defaultdict(list)

        # note: flow graph != call graph (vertex)
        self.flow_graph_index_by_address: dict[int, int] = {}
        self.flow_graph_address_by_index: dict[int, int] = {}

        # edges that come from the given basic block
        self.source_edges_by_basic_block_index: dict[int, list[BinExport2.FlowGraph.Edge]] = defaultdict(list)
        # edges that end up at the given basic block
        self.target_edges_by_basic_block_index: dict[int, list[BinExport2.FlowGraph.Edge]] = defaultdict(list)

        self.vertex_index_by_address: dict[int, int] = {}

        self.data_reference_index_by_source_instruction_index: dict[int, list[int]] = defaultdict(list)
        self.data_reference_index_by_target_address: dict[int, list[int]] = defaultdict(list)
        self.string_reference_index_by_source_instruction_index: dict[int, list[int]] = defaultdict(list)

        self.insn_address_by_index: dict[int, int] = {}
        self.insn_index_by_address: dict[int, int] = {}
        self.insn_by_address: dict[int, BinExport2.Instruction] = {}

        # from thunk address to target function address
        self.thunks: dict[int, int] = {}

        # must index instructions first
        self._index_insn_addresses()
        self._index_vertex_edges()
        self._index_flow_graph_nodes()
        self._index_flow_graph_edges()
        self._index_call_graph_vertices()
        self._index_data_references()
        self._index_string_references()
        self._index_thunks()

    def get_insn_address(self, insn_index: int) -> int:
        assert insn_index in self.insn_address_by_index, f"insn must be indexed, missing {insn_index}"
        return self.insn_address_by_index[insn_index]

    def get_basic_block_address(self, basic_block_index: int) -> int:
        basic_block: BinExport2.BasicBlock = self.be2.basic_block[basic_block_index]
        first_instruction_index: int = next(self.instruction_indices(basic_block))
        return self.get_insn_address(first_instruction_index)

    def _index_vertex_edges(self):
        for edge in self.be2.call_graph.edge:
            self.callers_by_vertex_index[edge.target_vertex_index].append(edge.source_vertex_index)
            self.callees_by_vertex_index[edge.source_vertex_index].append(edge.target_vertex_index)

    def _index_flow_graph_nodes(self):
        for flow_graph_index, flow_graph in enumerate(self.be2.flow_graph):
            function_address: int = self.get_basic_block_address(flow_graph.entry_basic_block_index)
            self.flow_graph_index_by_address[function_address] = flow_graph_index
            self.flow_graph_address_by_index[flow_graph_index] = function_address

    def _index_flow_graph_edges(self):
        for flow_graph in self.be2.flow_graph:
            for edge in flow_graph.edge:
                if not edge.HasField("source_basic_block_index") or not edge.HasField("target_basic_block_index"):
                    continue

                self.source_edges_by_basic_block_index[edge.source_basic_block_index].append(edge)
                self.target_edges_by_basic_block_index[edge.target_basic_block_index].append(edge)

    def _index_call_graph_vertices(self):
        for vertex_index, vertex in enumerate(self.be2.call_graph.vertex):
            if not vertex.HasField("address"):
                continue

            vertex_address: int = vertex.address
            self.vertex_index_by_address[vertex_address] = vertex_index

    def _index_data_references(self):
        for data_reference_index, data_reference in enumerate(self.be2.data_reference):
            self.data_reference_index_by_source_instruction_index[data_reference.instruction_index].append(
                data_reference_index
            )
            self.data_reference_index_by_target_address[data_reference.address].append(data_reference_index)

    def _index_string_references(self):
        for string_reference_index, string_reference in enumerate(self.be2.string_reference):
            self.string_reference_index_by_source_instruction_index[string_reference.instruction_index].append(
                string_reference_index
            )

    def _index_insn_addresses(self):
        # see https://github.com/google/binexport/blob/39f6445c232bb5caf5c4a2a996de91dfa20c48e8/binexport.cc#L45
        if len(self.be2.instruction) == 0:
            return

        assert self.be2.instruction[0].HasField("address"), "first insn must have explicit address"

        addr: int = 0
        next_addr: int = 0
        for idx, insn in enumerate(self.be2.instruction):
            if insn.HasField("address"):
                addr = insn.address
                next_addr = addr + len(insn.raw_bytes)
            else:
                addr = next_addr
                next_addr += len(insn.raw_bytes)
            self.insn_address_by_index[idx] = addr
            self.insn_index_by_address[addr] = idx
            self.insn_by_address[addr] = insn

    def _index_thunks(self):
        for addr, vertex_idx in self.vertex_index_by_address.items():
            vertex: BinExport2.CallGraph.Vertex = self.be2.call_graph.vertex[vertex_idx]

            if not is_thunk_vertex(vertex):
                continue

            curr_vertex_idx: int = vertex_idx
            for _ in range(THUNK_CHAIN_DEPTH_DELTA):
                thunk_callees: list[int] = self.callees_by_vertex_index[curr_vertex_idx]
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
                thunked_vertex: BinExport2.CallGraph.Vertex = self.be2.call_graph.vertex[thunked_vertex_idx]

                if not is_thunk_vertex(thunked_vertex):
                    assert thunked_vertex.HasField("address")

                    self.thunks[addr] = thunked_vertex.address
                    break

                curr_vertex_idx = thunked_vertex_idx

    @staticmethod
    def instruction_indices(basic_block: BinExport2.BasicBlock) -> Iterator[int]:
        """
        For a given basic block, enumerate the instruction indices.
        """
        for index_range in basic_block.instruction_index:
            if not index_range.HasField("end_index"):
                yield index_range.begin_index
                continue
            else:
                yield from range(index_range.begin_index, index_range.end_index)

    def basic_block_instructions(
        self, basic_block: BinExport2.BasicBlock
    ) -> Iterator[tuple[int, BinExport2.Instruction, int]]:
        """
        For a given basic block, enumerate the instruction indices,
        the instruction instances, and their addresses.
        """
        for instruction_index in self.instruction_indices(basic_block):
            instruction: BinExport2.Instruction = self.be2.instruction[instruction_index]
            instruction_address: int = self.get_insn_address(instruction_index)

            yield instruction_index, instruction, instruction_address

    def get_function_name_by_vertex(self, vertex_index: int) -> str:
        vertex: BinExport2.CallGraph.Vertex = self.be2.call_graph.vertex[vertex_index]
        name: str = f"sub_{vertex.address:x}"

        if is_thunk_vertex(vertex):
            if target := self.thunks.get(vertex.address):
                target_name = self.get_function_name_by_address(target)
                name = f"j_{target_name}"

        if vertex.HasField("mangled_name") and not vertex.mangled_name.startswith("sub_"):
            name = vertex.mangled_name

        if vertex.HasField("demangled_name") and not vertex.demangled_name.startswith("sub_"):
            name = vertex.demangled_name

        if vertex.HasField("library_index"):
            library: BinExport2.Library = self.be2.library[vertex.library_index]
            if library.HasField("name"):
                name = f"{library.name}!{name}"

        return name

    def get_function_name_by_address(self, address: int) -> str:
        if address not in self.vertex_index_by_address:
            return ""

        vertex_index: int = self.vertex_index_by_address[address]
        return self.get_function_name_by_vertex(vertex_index)

    def get_instruction_by_address(self, address: int) -> BinExport2.Instruction:
        assert address in self.insn_by_address, f"address must be indexed, missing {address:x}"
        return self.insn_by_address[address]


def find_be2_base_address(be2: BinExport2):
    sections_with_perms: Iterator[BinExport2.Section] = filter(lambda s: s.flag_r or s.flag_w or s.flag_x, be2.section)
    # assume the lowest address is the base address.
    # this works as long as BinExport doesn't record other
    # libraries mapped into memory.
    return min(s.address for s in sections_with_perms)


@dataclass
class MemoryRegion:
    # location of the bytes, potentially relative to a base address
    address: int
    buf: bytes

    @property
    def end(self) -> int:
        return self.address + len(self.buf)

    def contains(self, address: int) -> bool:
        # note: address must be relative to any base address
        return self.address <= address < self.end


class ReadMemoryError(ValueError): ...


class AddressNotMappedError(ReadMemoryError): ...


@dataclass
class AddressSpace:
    """
    Simple accessor to mapped executable files.

    BinExport2 doesn't capture file bytes, but it does reference
    bytes by virtual addresses. This class makes it easy to read
    the data at those references.

    Addresses are relative to the `base_address` field here,
    so provide RVAs (not VAs). Use `find_be2_base_address` to
    when working with BinExport2 instances to map a VA to an RVA.
    """

    base_address: int
    memory_regions: tuple[MemoryRegion, ...]

    def read_memory(self, address: int, length: int) -> bytes:
        rva: int = address - self.base_address
        for region in self.memory_regions:
            if region.contains(rva):
                offset: int = rva - region.address
                return region.buf[offset : offset + length]

        raise AddressNotMappedError(address)

    @classmethod
    def from_pe(cls, pe: PE, base_address: int):
        regions: list[MemoryRegion] = []
        for section in pe.sections:
            address: int = section.VirtualAddress
            size: int = section.Misc_VirtualSize
            buf: bytes = section.get_data()

            if len(buf) != size:
                # pad the section with NULLs
                # assume page alignment is already handled.
                # might need more hardening here.
                buf += b"\x00" * (size - len(buf))

            regions.append(MemoryRegion(address, buf))

        return cls(base_address, tuple(regions))

    @classmethod
    def from_elf(cls, elf: ELFFile, base_address: int):
        regions: list[MemoryRegion] = []

        # ELF segments are for runtime data,
        # ELF sections are for link-time data.
        for segment in elf.iter_segments():
            # assume p_align is consistent with addresses here.
            # otherwise, should harden this loader.
            segment_rva: int = segment.header.p_vaddr
            segment_size: int = segment.header.p_memsz
            segment_data: bytes = segment.data()

            if len(segment_data) < segment_size:
                # pad the section with NULLs
                # assume page alignment is already handled.
                # might need more hardening here.
                segment_data += b"\x00" * (segment_size - len(segment_data))

            regions.append(MemoryRegion(segment_rva, segment_data))

        return cls(base_address, tuple(regions))

    @classmethod
    def from_buf(cls, buf: bytes, base_address: int):
        if buf.startswith(b"MZ"):
            pe: PE = PE(data=buf)
            return cls.from_pe(pe, base_address)
        elif buf.startswith(b"\x7fELF"):
            elf: ELFFile = ELFFile(io.BytesIO(buf))
            return cls.from_elf(elf, base_address)
        else:
            raise NotImplementedError("file format address space")
