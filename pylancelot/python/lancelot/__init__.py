from ._lib import binexport2_from_bytes as _binexport2_bytes_from_bytes
from .be2utils.binexport2_pb2 import BinExport2


def get_binexport2_bytes_from_bytes(buf: bytes, sig_paths=None, function_hints=None) -> bytes:
    """Get the Lancelot workspace as a BinExport2-encoded buffer"""
    return _binexport2_bytes_from_bytes(buf, sig_paths=sig_paths, function_hints=function_hints)


def get_binexport2_from_bytes(buf: bytes, sig_paths=None, function_hints=None) -> BinExport2:
    """Get the Lancelot workspace as a BinExport2 instance"""
    be2: BinExport2 = BinExport2()
    be2.ParseFromString(get_binexport2_bytes_from_bytes(buf, sig_paths=sig_paths, function_hints=function_hints))
    return be2
