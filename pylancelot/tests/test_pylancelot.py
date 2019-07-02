import pylancelot


def test_workspace():
    ws = pylancelot.from_bytes('foo.bin', b'\xEB\xFE')
    assert str(ws) == 'PyWorkspace(filename: foo.bin loader: Windows/x32/Raw)'
    assert repr(ws) == 'PyWorkspace(filename: foo.bin loader: Windows/x32/Raw)'


def test_filename():
    ws = pylancelot.from_bytes('foo.bin', b'\xEB\xFE')
    assert ws.filename == 'foo.bin'


def test_loader():
    ws = pylancelot.from_bytes('foo.bin', b'\xEB\xFE')
    assert ws.loader == 'Windows/x32/Raw'


def test_base_address():
    ws = pylancelot.from_bytes('foo.bin', b'\xEB\xFE')
    assert ws.base_address == 0x0


def test_sections():
    ws = pylancelot.from_bytes('foo.bin', b'\xEB\xFE')
    sec = ws.sections[0]

    assert sec.addr == 0x0
    assert sec.length == 0x2
    # TODO: flags
    assert sec.perms == 0x7
    assert sec.name == 'raw'
    assert str(sec) == 'PySection(addr: 0x0 length: 0x2 perms: 0x7 name: raw)'
    assert repr(sec) == 'PySection(addr: 0x0 length: 0x2 perms: 0x7 name: raw)'
