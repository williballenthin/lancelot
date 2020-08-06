import pytest

import pylancelot

import fixtures
from fixtures import *


def test_invalid_pe():
    with pytest.raises(ValueError):
        pylancelot.from_bytes(b"")

    with pytest.raises(ValueError):
        pylancelot.from_bytes(b"MZ\x9000")

    try:
        pylancelot.from_bytes(b"")
    except ValueError as e:
        assert str(e) == "failed to fill whole buffer"


def test_load_pe(k32):
    pylancelot.from_bytes(k32)