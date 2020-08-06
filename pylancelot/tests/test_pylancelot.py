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