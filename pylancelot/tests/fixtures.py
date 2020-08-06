import os.path

import pytest

import pylancelot


CD = os.path.dirname(__file__)


with open(os.path.join(CD, 'data', 'k32.dll_'), 'rb') as f:
    K32 = f.read()


@pytest.fixture
def k32():
    return K32
