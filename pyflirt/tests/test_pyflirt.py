import textwrap

import flirt


def test_parse_pat():
    pat = textwrap.dedent("""
        518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 21 B4FE 006E :0000 __EH_prolog3_GS_align ^0041 ___security_cookie ........33C5508941FC8B4DF0895DF08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
        518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 1F E4CF 0063 :0000 __EH_prolog3_align ^003F ___security_cookie ........33C5508B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
        518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 22 E4CE 006F :0000 __EH_prolog3_catch_GS_align ^0042 ___security_cookie ........33C5508941FC8B4DF08965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
        518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 20 6562 0067 :0000 __EH_prolog3_catch_align ^0040 ___security_cookie ........33C5508965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
        ---
    """).strip()

    sigs = flirt.parse_pat(pat)
    matcher = flirt.compile(sigs)
    buf = bytes([
        # apds.dll / 4FD932C41DF96D019DC265E26E94B81B
        # __EH_prolog3_catch_align
        
        # first 0x20
        0x51, 0x8B, 0x4C, 0x24, 0x0C, 0x89, 0x5C, 0x24,
        0x0C, 0x8D, 0x5C, 0x24, 0x0C, 0x50, 0x8D, 0x44,
        0x24, 0x08, 0xF7, 0xD9, 0x23, 0xC1, 0x8D, 0x60,
        0xF8, 0x8B, 0x43, 0xF0, 0x89, 0x04, 0x24, 0x8B,
        # crc16 start
        0x43, 0xF8, 0x50, 0x8B, 0x43, 0xFC, 0x8B, 0x4B,
        0xF4, 0x89, 0x6C, 0x24, 0x0C, 0x8D, 0x6C, 0x24,
        0x0C, 0xC7, 0x44, 0x24, 0x08, 0xFF, 0xFF, 0xFF,
        0xFF, 0x51, 0x53, 0x2B, 0xE0, 0x56, 0x57, 0xA1,
        # crc end
        0xD4, 0xAD, 0x19, 0x01, 0x33, 0xC5, 0x50, 0x89,
        0x65, 0xF0, 0x8B, 0x43, 0x04, 0x89, 0x45, 0x04,
        0xFF, 0x75, 0xF4, 0x64, 0xA1, 0x00, 0x00, 0x00,
        0x00, 0x89, 0x45, 0xF4, 0x8D, 0x45, 0xF4, 0x64,
        0xA3, 0x00, 0x00, 0x00, 0x00, 0xC3
    ])

    matches = matcher.match(buf)
    assert len(matches) == 1

    match = matches[0]
    assert match.names[0] == ("__EH_prolog3_catch_align", "public", 0)
    assert str(match) == 'FlirtSignature("__EH_prolog3_catch_align")'