import contextlib

import pytest
import lancelot


def test_binexport2(k32):
    buf = lancelot.binexport2_from_bytes(k32)
    assert buf is not None
    assert isinstance(buf, bytes)


def test_invalid_pe():
    with pytest.raises(ValueError):
        lancelot.binexport2_from_bytes(b"")

    with pytest.raises(ValueError):
        lancelot.binexport2_from_bytes(b"MZ\x9000")

    with contextlib.suppress(ValueError):
        lancelot.binexport2_from_bytes(b"")


def test_load_pe(k32):
    lancelot.binexport2_from_bytes(k32)


def test_load_coff(altsvc):
    lancelot.binexport2_from_bytes(altsvc)


def test_hint_function(k32):
    # 7dd70e00  int32_t* __stdcall _GetStartupInfoA@4(int32_t* arg1)
    # 7dd70e00  8bff               mov     edi, edi
    # 7dd70e02  55                 push    ebp {__saved_ebp}
    lancelot.binexport2_from_bytes(k32, function_hints=[0x7dd70e02])
