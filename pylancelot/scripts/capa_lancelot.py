import sys
import types
import logging
import argparse

import capa
import capa.main
import pefile
import colorama
import lancelot
import capa.features.extractors.strings
from capa.features import String, Characteristic
from capa.features.file import Export, Import, Section


logger = logging.getLogger("capa.lancelot")


def extract_file_embedded_pe(buf, pe):
    buf = buf[2:]

    total_offset = 2
    while True:
        try:
            offset = buf.index(b"MZ")
        except ValueError:
            return
        else:
            rest = buf[offset:]
            total_offset += offset

            try:
                _ = pefile.PE(data=b"A" + rest)
            except:
                pass
            else:
                yield Characteristic("embedded pe"), total_offset

            buf = rest[2:]
            total_offset += 2


def extract_file_export_names(buf, pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return

    base_address = pe.OPTIONAL_HEADER.ImageBase
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        # TODO: handle ordinals
        yield Export(exp.name.decode('ascii')), base_address + exp.address


def extract_file_import_names(buf, pe):
    base_address = pe.OPTIONAL_HEADER.ImageBase
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        libname = entry.dll.decode('ascii')
        for imp in entry.imports:
            # TODO: ordinals
            impname = imp.name.decode("ascii")
            impaddr = base_address + imp.address
            yield Import("%s!%s" % (libname, impname)), impaddr
            yield Import("%s" % (impname)), impaddr


def extract_file_section_names(buf, pe):
    base_address = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        yield Section(section.Name.partition(b"\x00")[0].decode("ascii")), base_address + section.VirtualAddress


def extract_file_strings(buf, pe):
    for s in capa.features.extractors.strings.extract_ascii_strings(buf):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(buf):
        yield String(s.s), s.offset


def extract_file_features(buf):
    pe = pefile.PE(data=buf)
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(buf, pe):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
)


class BB(object):
    """extend the lancelot.BasicBlock with an __int__ method to access the address"""
    def __init__(self, bb):
        super(BB, self).__init__()
        self.address = bb.address
        self.length = bb.length
        self.predecessors = bb.predecessors
        self.successors = bb.successors

    def __int__(self):
        return self.address


class LancelotFeatureExtractor(capa.features.extractors.FeatureExtractor):
    def __init__(self, buf, path):
        super(LancelotFeatureExtractor, self).__init__()
        self.buf = buf
        self.ws = lancelot.from_bytes(buf)
        self.path = path

    def get_base_address(self):
        return self.ws.base_address

    def extract_file_features(self):
        for feature, va in extract_file_features(self.buf):
            yield feature, va

    def get_functions(self):
        for va in self.ws.get_functions():
            yield va

    def extract_function_features(self, f):
        return []
        for feature, va in capa.features.extractors.viv.function.extract_features(f):
            yield feature, va

    def get_basic_blocks(self, f):
        cfg = self.ws.build_cfg(f)
        for bb in cfg.basic_blocks.values():
            yield BB(bb)

    def extract_basic_block_features(self, f, bb):
        return []
        for feature, va in capa.features.extractors.viv.basicblock.extract_features(f, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        va = bb.address
        while va <= bb.address + bb.length:
            try:
                insn = self.ws.read_insn(va)
            except ValueError:
                logger.warning("failed to read instruction at 0x%x", va)
                return

            yield insn
            va += insn.length

    def extract_insn_features(self, f, bb, insn):
        return []
        for feature, va in capa.features.extractors.viv.insn.extract_features(f, bb, insn):
            yield feature, va


def get_lancelot_extractor(sample_path):
    with open(sample_path, "rb") as f:
        buf = f.read()

    return LancelotFeatureExtractor(buf, sample_path)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="capa using lancelot for code analysis",
    )
    parser.add_argument("rules", type=str, help="path to rules directory")
    parser.add_argument("sample", type=str, help="path to sample to analyze")
    parser.add_argument("-t", "--tag", type=str, help="filter on rule meta field values")
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose result document (no effect with --json)"
    )
    parser.add_argument(
        "-vv", "--vverbose", action="store_true", help="enable very verbose result document (no effect with --json)"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    parser.add_argument(
        "--color",
        type=str,
        choices=("auto", "always", "never"),
        default="auto",
        help="enable ANSI color codes in results, default: only during interactive session",
    )
    args = parser.parse_args(args=argv)

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    rules_path = args.rules
    logger.debug("using rules path: %s", rules_path)

    try:
        rules = capa.main.get_rules(rules_path)
        rules = capa.rules.RuleSet(rules)
        logger.debug("successfully loaded %s rules", len(rules))
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.debug("selected %s rules", len(rules))
            for i, r in enumerate(rules.rules, 1):
                logger.debug(" %d. %s", i, r)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    extractor = get_lancelot_extractor(args.sample)
    meta = capa.main.collect_metadata(argv, args.sample, args.rules, format, extractor)

    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=args.quiet)
    meta["analysis"].update(counts)

    if capa.main.has_file_limitation(rules, capabilities):
        # bail if capa encountered file limitation e.g. a packed binary
        # do show the output in verbose mode, though.
        if not (args.verbose or args.vverbose or args.json):
            return -1

    if args.color == "always":
        colorama.init(strip=False)
    elif args.color == "auto":
        # colorama will detect:
        #  - when on Windows console, and fixup coloring, and
        #  - when not an interactive session, and disable coloring
        # renderers should use coloring and assume it will be stripped out if necessary.
        colorama.init()
    elif args.color == "never":
        colorama.init(strip=True)
    else:
        raise RuntimeError("unexpected --color value: " + args.color)

    if args.json:
        print(capa.render.render_json(meta, rules, capabilities))
    elif args.vverbose:
        print(capa.render.render_vverbose(meta, rules, capabilities))
    elif args.verbose:
        print(capa.render.render_verbose(meta, rules, capabilities))
    else:
        print(capa.render.render_default(meta, rules, capabilities))
    colorama.deinit()

    logger.debug("done.")

    return 0


if __name__ == "__main__":
    sys.exit(main())