import sys

import lancelot

with open(sys.argv[1], "rb") as f:
    buf = f.read()
    be2 = lancelot.get_binexport2_from_bytes(buf)


for vertex_index, vertex in enumerate(be2.call_graph.vertex):
    if not vertex.HasField("address"):
        continue

    vertex_address: int = vertex.address
    print(hex(vertex_address))
