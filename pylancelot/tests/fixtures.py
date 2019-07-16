import os
import os.path

import pytest

import pylancelot


CD = os.path.dirname(__file__)


@pytest.fixture
def k32():
    path = os.path.join(CD, 'data', 'k32.dll_')
    with open(path, 'rb') as f:
        buf = f.read()

    return pylancelot.from_bytes('k32.dll', buf)
