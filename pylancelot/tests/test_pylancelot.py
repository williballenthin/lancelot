import pefile
import pytest

import lancelot

from fixtures import *


def test_invalid_pe():
    with pytest.raises(ValueError):
        lancelot.from_bytes(b"")

    with pytest.raises(ValueError):
        lancelot.from_bytes(b"MZ\x9000")

    try:
        lancelot.from_bytes(b"")
    except ValueError as e:
        assert str(e) == "failed to fill whole buffer"


def test_load_pe(k32):
    lancelot.from_bytes(k32)


def test_arch(k32):
    ws = lancelot.from_bytes(k32)
    assert "Returns: str" in lancelot.PE.arch.__doc__
    assert ws.arch == "x64"


def test_base_address(k32):
    ws = lancelot.from_bytes(k32)
    assert "Returns: int" in lancelot.PE.base_address.__doc__
    assert ws.base_address == 0x180000000


def test_functions(k32):
    ws = lancelot.from_bytes(k32)

    assert "Returns: List[int]" in ws.get_functions.__doc__
    functions = ws.get_functions()

    # IDA identifies 2326
    # lancelot identifies around 2200
    assert len(functions) > 2000

    # this is _security_check_cookie
    assert 0x180020250 in functions

    # exports identified by pefile should be identified as functions
    pe = pefile.PE(data=k32)
    base_address = pe.OPTIONAL_HEADER.ImageBase
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if export.forwarder is not None:
            continue
        address = base_address + export.address
        assert address in functions


def test_flow_const():
    assert lancelot.FLOW_TYPE_FALLTHROUGH == 0
    assert lancelot.FLOW_TYPE_CALL == 1


def test_cfg(k32):
    ws = lancelot.from_bytes(k32)

    assert "Returns: CFG" in ws.build_cfg.__doc__
    # this is _report_gsfailure
    # it has a diamond shape
    cfg = ws.build_cfg(0x1800202B0)

    assert cfg.address == 0x1800202B0
    assert len(cfg.basic_blocks) == 4

    assert 0x1800202B0 in cfg.basic_blocks
    assert 0x180020334 in cfg.basic_blocks
    assert 0x1800202F3 in cfg.basic_blocks
    assert 0x180020356 in cfg.basic_blocks

    bb0 = cfg.basic_blocks[0x1800202B0]
    assert 0x180020334 in map(lambda flow: flow[lancelot.FLOW_VA], bb0.successors)
    assert 0x1800202F3 in map(lambda flow: flow[lancelot.FLOW_VA], bb0.successors)


def test_call_graph(k32):
    ws = lancelot.from_bytes(k32)

    assert "Returns: CallGraph" in ws.build_call_graph.__doc__

    cg = ws.build_call_graph()
    assert len(cg.calls_to[0x180001068]) == 2
    assert 0x18000F775 in cg.calls_to[0x180001068]
    assert 0x180060504 in cg.calls_to[0x180001068]
    assert 0x180001068 in cg.calls_from[0x180060504]
    assert 0x1800602C0 in cg.call_instruction_functions[0x180060504]
    assert 0x180060504 in cg.function_call_instructions[0x1800602C0]


def test_read_insn(k32):
    ws = lancelot.from_bytes(k32)

    assert "Returns: Instruction" in ws.read_insn.__doc__

    with pytest.raises(ValueError):
        ws.read_insn(0x0)

    # .text:00000001800202B0 48 89 4C 24 08  mov     [rsp+arg_0], rcx
    insn = ws.read_insn(0x1800202B0)
    assert insn.address == 0x1800202B0
    assert insn.length == 5
    assert insn.mnemonic == "mov"

    operands = insn.operands
    assert len(operands) == 2

    # op[0] == [rsp + 8]
    assert operands[0][lancelot.OPERAND_TYPE] == lancelot.OPERAND_TYPE_MEMORY
    assert operands[0][lancelot.OPERAND_SIZE] == 64
    assert operands[0][lancelot.MEMORY_OPERAND_BASE] == "rsp"
    assert operands[0][lancelot.MEMORY_OPERAND_DISP] == 8

    # op[1] == rcx
    assert operands[1][lancelot.OPERAND_TYPE] == lancelot.OPERAND_TYPE_REGISTER
    assert operands[1][lancelot.OPERAND_SIZE] == 64
    assert operands[1][lancelot.REGISTER_OPERAND_REGISTER] == "rcx"

    assert operands == ((1, 64, 'rsp', None, 'ss', 0, 8), (3, 64, 'rcx'))


def test_read_bytes(k32):
    ws = lancelot.from_bytes(k32)

    assert "Returns: bytes" in ws.read_bytes.__doc__

    with pytest.raises(ValueError):
        ws.read_bytes(0x0, 1)

    assert ws.read_bytes(0x180000000, 2) == b"MZ"


def test_read_pointer(k32):
    ws = lancelot.from_bytes(k32)

    assert "Returns: int" in ws.read_pointer.__doc__

    with pytest.raises(ValueError):
        ws.read_pointer(0x0)

    assert ws.read_pointer(0x180076008) == 0x18007D630


def test_probe(k32):
    ws = lancelot.from_bytes(k32)

    assert ws.probe(0x180000000) & lancelot.PERMISSION_READ != 0
    assert ws.probe(0x180000000) & lancelot.PERMISSION_WRITE == 0
    assert ws.probe(0x180000000) & lancelot.PERMISSION_EXECUTE == 0

    # part of some functino
    assert ws.probe(0x1800202B0) & lancelot.PERMISSION_READ != 0
    assert ws.probe(0x1800202B0) & lancelot.PERMISSION_WRITE == 0
    assert ws.probe(0x1800202B0) & lancelot.PERMISSION_EXECUTE != 0


def test_insn_int(k32):
    ws = lancelot.from_bytes(k32)
    assert int(ws.read_insn(0x1800202B0)) == 0x1800202B0
