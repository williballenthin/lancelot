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

