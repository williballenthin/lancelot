import sys
import gzip
import json

with open(sys.argv[1], "rb") as f:
    doc = json.loads(gzip.decompress(f.read()))

functions = set([])
basic_blocks  = set([])
instructions  = set([])
for f in doc["module"].get("fuc", []):
    print("function: " + hex(int(f["va"])))

    for bb in f.get("bb", []):
        print("basic block: " + hex(int(bb["va"])))

        for insn in bb.get("instructions", []):
            print("instruction: " + hex(int(insn["va"])))
