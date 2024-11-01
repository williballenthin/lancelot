import sys

import lancelot

with open(sys.argv[1], "rb") as f:
    buf = f.read()


be2 = lancelot.get_binexport2_bytes_from_bytes(buf)
with open(sys.argv[2], "wb") as f:
    f.write(be2)

print(f"wrote {len(be2)} bytes!")
