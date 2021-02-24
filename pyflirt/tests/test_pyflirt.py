import pytest

import flirt

from fixtures import __EH_prolog3_sig
from fixtures import __EH_prolog3_pat
from fixtures import __EH_prolog3_catch_align


def test_parse_pat(__EH_prolog3_pat):
    sigs = flirt.parse_pat(__EH_prolog3_pat)
    matcher = flirt.compile(sigs)

    matches = matcher.match(__EH_prolog3_catch_align)
    assert len(matches) == 1

    match = matches[0]
    assert match.names[0] == ("__EH_prolog3_catch_align", "public", 0)
    assert str(match) == 'FlirtSignature("__EH_prolog3_catch_align")'


def test_parse_sig(__EH_prolog3_sig):
    sigs = flirt.parse_sig(__EH_prolog3_sig)
    matcher = flirt.compile(sigs)

    matches = matcher.match(__EH_prolog3_catch_align)
    assert len(matches) == 1

    match = matches[0]
    assert match.names[0] == ("__EH_prolog3_catch_align", "public", 0)
    assert str(match) == 'FlirtSignature("__EH_prolog3_catch_align")'