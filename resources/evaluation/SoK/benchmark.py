import os
import sys
import gzip
import json
import os.path
import collections
from collections import namedtuple

import tqdm
import yaml
import pandas
import lancelot
import tabulate

Layout = namedtuple("Layout", ["functions", "basic_blocks", "instructions"])


frameworks = {
    "lancelot": "lancelot",
    # "ida": "IDA Pro (v7.5)",
    # "viv": "vivisect (v0.0.20200804)"
}


def find_by_suffix(path, suffix):
    return os.path.join(path, [f for f in os.listdir(path) if f.endswith(suffix)][0])


def get_gt_layout(path):
    with open(find_by_suffix(path, ".gt.json.gz"), "rb") as f:
        doc = json.loads(gzip.decompress(f.read()))

    functions = set([])
    basic_blocks = set([])
    instructions = set([])
    for f in doc["module"].get("fuc", []):
        functions.add(int(f["va"]))
        for bb in f.get("bb", []):
            basic_blocks.add(int(bb["va"]))
            for insn in bb.get("instructions", []):
                instructions.add(int(insn["va"]))

    return Layout(functions, basic_blocks, instructions)


def get_lancelot_workspace(path):
    try:
        with open(find_by_suffix(path, ".exe"), "rb") as f:
            return lancelot.from_bytes(f.read())
    except IndexError:
        pass

    with open(find_by_suffix(path, ".dll"), "rb") as f:
        return lancelot.from_bytes(f.read())


def get_lancelot_layout(path):
    ws = get_lancelot_workspace(path)

    functions = set([])
    basic_blocks = set([])
    instructions = set([])
    for f in ws.get_functions():
        functions.add(f)
        try:
            cfg = ws.build_cfg(f)
        except:
            continue
        else:
            for bb in cfg.basic_blocks.values():
                basic_blocks.add(bb.address)

                va = bb.address
                while va < bb.address + bb.length:
                    try:
                        insn = ws.read_insn(va)
                    except ValueError:
                        break
                    instructions.add(va)
                    va += insn.length

    return Layout(functions, basic_blocks, instructions)


def precision(found, wanted):
    return len(wanted.intersection(found)) / float(len(found))


def recall(found, wanted):
    return len(wanted.intersection(found)) / float(len(wanted))


def compute_stats(framework, path):
    if framework == "lancelot":
        found = get_lancelot_layout(path)
    elif framework == "viv":
        found = get_viv_layout(path)
    elif framework == "ida":
        found = get_ida_layout(path)
    else:
        raise RuntimeError("unexpected framework: " + framework)

    wanted = get_gt_layout(path)
    return {
        "functions": {
            "precision": precision(found.functions, wanted.functions),
            "recall": recall(found.functions, wanted.functions),
        },
        "basic_blocks": {
            "precision": precision(found.basic_blocks, wanted.basic_blocks),
            "recall": recall(found.basic_blocks, wanted.basic_blocks),
        },
        "instructions": {
            "precision": precision(found.instructions, wanted.instructions),
            "recall": recall(found.instructions, wanted.instructions),
        },
    }


def render_stats(stats):
    return yaml.dump(stats, default_flow_style=False)


def collect_tests():
    base = "SoK-windows-testsuite/"
    for build in os.listdir(base):
        build = os.path.join(base, build)
        if not os.path.isdir(build):
            continue
        for exe in os.listdir(build):
            exe = os.path.join(build, exe)
            yield exe


if __name__ == "__main__":
    results = collections.defaultdict(dict)

    for test in tqdm.tqdm(list(collect_tests())):
        # filter tests by first (optional) cli argument
        if len(sys.argv) > 1:
            if sys.argv[1] not in test:
                continue

        for framework in frameworks.keys():
            results[framework][test] = compute_stats(framework, test)

    def collect_pandas(results):
        return pandas.DataFrame.from_records(
            {
                "functions.precision": v["functions"]["precision"],
                "functions.recall": v["functions"]["recall"],
                "basic_blocks.precision": v["basic_blocks"]["precision"],
                "basic_blocks.recall": v["basic_blocks"]["recall"],
                "instructions.precision": v["instructions"]["precision"],
                "instructions.recall": v["instructions"]["recall"],
                "test": k,
            }
            for k, v in results.items()
        )

    for fw in frameworks.keys():
        if fw not in results:
            continue
        pd = collect_pandas(results[fw])
        print(f"{frameworks[fw]} vs SoK test suite")
        print("  functions:")
        print("    precision: %0.3f" % (pd["functions.precision"].mean()))
        print("    recall:    %0.3f" % (pd["functions.recall"].mean()))
        print("  basic blocks:")
        print("    precision: %0.3f" % (pd["basic_blocks.precision"].mean()))
        print("    recall:    %0.3f" % (pd["basic_blocks.recall"].mean()))
        print("  instructions:")
        print("    precision: %0.3f" % (pd["instructions.precision"].mean()))
        print("    recall:    %0.3f" % (pd["instructions.recall"].mean()))

    rows = []
    for test in results["lancelot"].keys():
        frecall = results["lancelot"][test]["functions"]["recall"]
        rows.append((frecall, test))

    rows = sorted(rows)

    print("")
    print("worst performing function recall:")
    print(tabulate.tabulate(rows[:20]))

    ####

    rows = []
    for test in results["lancelot"].keys():
        fprecision = results["lancelot"][test]["functions"]["precision"]
        rows.append((fprecision, test))

    rows = sorted(rows)

    print("")
    print("worst performing function precision:")
    print(tabulate.tabulate(rows[:20]))