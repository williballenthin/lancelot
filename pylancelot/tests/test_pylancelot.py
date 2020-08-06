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
    assert ws.arch == "x64"


def test_functions(k32):
    ws = lancelot.from_bytes(k32)
    functions = ws.functions

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