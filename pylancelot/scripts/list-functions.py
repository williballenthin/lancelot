import sys

import lancelot


with open(sys.argv[1], 'rb') as f:
    buf = f.read()

ws = lancelot.from_bytes(buf)
for function in ws.get_functions():
    print(hex(function))
