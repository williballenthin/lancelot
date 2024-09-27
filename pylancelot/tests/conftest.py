import os.path

import pytest

CD = os.path.dirname(__file__)


with open(os.path.join(CD, "data", "k32.dll_"), "rb") as f:
    K32 = f.read()


with open(os.path.join(CD, "data", "altsvc.c.obj"), "rb") as f:
    ALTSVC = f.read()


@pytest.fixture
def k32():
    return K32


@pytest.fixture
def altsvc():
    return ALTSVC
