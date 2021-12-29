import * as React from "react";
import { useCallback, useMemo } from "react";
import ReactDOM from "react-dom";
import { Provider, useSelector, useDispatch } from "react-redux";
import { configureStore, createSlice, Dispatch } from "@reduxjs/toolkit";
import { HotkeysTarget2, HotkeysProvider } from "@blueprintjs/core";
import { DockLayout, DockMode } from "rc-dock";
import "rc-dock/dist/rc-dock.css";
import { FixedSizeList as List } from "react-window";
import AutoSizer from "react-virtualized-auto-sizer";

import * as Utils from "../../components/utils";
import * as Settings from "../../components/settings";
import * as Metrics from "../../components/metrics";
import { LocationOmnibar, Location } from "../../components/omnibar";

import init, * as Lancelot from "../../../../jslancelot/pkg/jslancelot";
import NOP from "./nop.bin";
import { Canvas } from "../../components/canvas";

export const APP = {
    set_theme: (name: string) => {
        document.getElementsByTagName("html")[0].className = `lancelot-theme-${name}`;
        Settings.set("theme", name);
    },
};

// helpers for jslancelot
type u64 = bigint | BigInt;
type address = u64;

interface AppState {
    address: address;
    address_history: address[];
}

export const { actions, reducer } = createSlice({
    name: "app",
    initialState: {
        address: BigInt(0x0),
        address_history: [],
    },
    reducers: {
        set_address: (state: AppState, action) => {
            // TODO: can't store BigInts in the store
            state.address = action.payload;
            state.address_history.push(action.payload);
        },
        pop_history: (state: AppState) => {
            if (state.address_history.length > 0) {
                state.address = state.address_history[state.address_history.length - 1];
                state.address_history.pop();
            }
        },
    },
});

const store = configureStore({
    reducer,
});

interface Dispatches {
    dispatch: Dispatch<any>;
}

// an address that may be valid in this workspace.
const Address = ({ address, dispatch }: { address: address } & Dispatches) => (
    <a className="lancelot-address bp4-monospace-text" onDoubleClick={() => dispatch(actions.set_address(address))}>
        0x{address.toString(0x10)}
    </a>
);

// a size of an item or delta/difference between two addresses.
const Size = ({ size }: { size: u64 | number }) => (
    <span className="lancelot-size bp4-monospace-text">0x{size.toString(0x10)}</span>
);

// the name of a location for which the address is known.
const NamedLocation = ({ name, address, dispatch }: { name: string; address: address } & Dispatches) => (
    <a
        className="lancelot-named-location bp4-monospace-text"
        onDoubleClick={() => dispatch(actions.set_address(address))}
    >
        {name}
    </a>
);

// these things should not change.
interface Workspace {
    buf: Uint8Array;
    arch: string;
    functions: address[];
    sections: Lancelot.Section[];
    strings: Lancelot.String[];
    layout: Lancelot.Layout;
    pe: Lancelot.PE;

    bb_by_address: Map<bigint, Lancelot.BasicBlock>;
    bbs_by_insn: Map<bigint, bigint[]>;
    functions_by_bb: Map<bigint, bigint[]>;
}

const HexViewRow = ({ index, style, data }: any) => {
    const { ws, dispatch } = data;
    const row_address = ws.pe.base_address + BigInt(0x10 * index);
    const buf = ws.pe.read_bytes(row_address, 0x10);

    const hex: string[] = [];
    const ascii: string[] = [];

    for (const b of buf) {
        hex.push(Utils.RENDERED_HEX[b]);
        ascii.push(Utils.RENDERED_ASCII[b]);
    }

    const hex_column = hex.join(" ");
    const ascii_column = ascii.join("");

    return (
        <div style={style} className="bp4-monospace-text">
            <Address address={row_address} dispatch={dispatch} /> <span>{hex_column}</span> <span>{ascii_column}</span>
        </div>
    );
};

class HexView extends React.Component<{ ws: Workspace; address: address } & Dispatches, any> {
    ref: React.RefObject<any>;

    constructor(props: any) {
        super(props);
        this.ref = React.createRef();
    }

    render() {
        const { address, ws } = this.props;
        const { dispatch } = this.props;

        const max_address: bigint = ws.sections
            .map((section: Lancelot.Section) => section.virtual_range.end)
            .sort()
            .reverse()[0] as bigint;

        const virtual_size = max_address - (ws.pe.base_address as bigint);
        const row_count = virtual_size / BigInt(0x10);

        // TODO: memoize?

        return (
            <AutoSizer>
                {({ height }: { height: number }) => (
                    <div className="lancelot-hex-view">
                        <List
                            ref={this.ref}
                            height={height}
                            width={640 /* empirical */}
                            itemSize={18 /* empirical */}
                            itemData={{ ws, address, dispatch }}
                            itemCount={Number(row_count)}
                        >
                            {HexViewRow}
                        </List>
                    </div>
                )}
            </AutoSizer>
        );
    }

    componentDidUpdate() {
        const { address, ws } = this.props;
        const offset = (address as bigint) - (ws.pe.base_address as bigint);
        const row_offset = offset / BigInt(0x10);
        this.ref.current.scrollToItem(Number(row_offset), "start");
    }
}

const DisassemblyView = (props: { ws: Workspace; address: address; size?: number } & Dispatches) => {
    const { address, ws, size = 0x100 } = props;
    const { dispatch } = props;

    let insn_address = address;
    const bbs = ws.bbs_by_insn.get(address as bigint);
    if (bbs !== undefined) {
        // TODO: assuming the first matching BB/function
        const functions = ws.functions_by_bb.get(bbs[0]);
        if (functions !== undefined) {
            const fva = functions[0];
            // when we find a containing function
            // jump to that instead
            // TODO: use better logic.
            insn_address = fva;
        }
    }

    const insns = [];
    let error: any = null;
    while (insn_address < (address as bigint) + BigInt(size)) {
        try {
            const insn = ws.pe.read_insn(insn_address);
            insns.push(insn);
            (insn_address as bigint) += BigInt(insn.size);
        } catch (err) {
            error = err;
            break;
        }
    }

    return (
        <div
            className="lancelot-disassembly-view"
            style={{ height: "100%", width: "100%", overflowY: "scroll", overflowX: "scroll", whiteSpace: "nowrap" }}
        >
            <p>
                disassembly@
                <Address address={address} dispatch={dispatch} />:
            </p>
            <div>
                {insns.map((insn) => (
                    <React.Fragment key={insn.address.toString()}>
                        <span className="bp4-monospace-text">
                            <Address address={insn.address} dispatch={dispatch} />
                            &nbsp; &nbsp;
                            <code style={{ whiteSpace: "pre" }}>
                                {Utils.hex(insn.bytes.slice(0, 8)).padEnd(24, " ")}
                            </code>
                            &nbsp; &nbsp;
                            <code>{insn.string}</code>
                        </span>
                        <br />
                    </React.Fragment>
                ))}
            </div>
            {error !== null ? <p>{error.toString()}</p> : ""}
        </div>
    );
};

const GraphView = (props: { ws: Workspace; address: address; size?: number } & Dispatches) => {
    return (
        <div className="lancelot-graph-view" style={{ height: "100%", width: "100%" }}>
            <Canvas>
                <div
                    style={{
                        backgroundColor: "red",
                        height: "100px",
                        width: "100px",
                        top: "200px",
                        left: "200px",
                        position: "relative",
                    }}
                ></div>
            </Canvas>
        </div>
    );
};

const SectionsView = ({ ws, dispatch }: { ws: Workspace } & Dispatches) => (
    <table>
        <thead>
            <tr>
                <th>name</th>
                <th>start</th>
                <th>end</th>
                <th>size</th>
            </tr>
        </thead>
        <tbody>
            {ws.sections.map((section: Lancelot.Section) => (
                <tr key={section.name}>
                    <td>
                        <NamedLocation name={section.name} address={section.virtual_range.start} dispatch={dispatch} />
                    </td>
                    <td>
                        <Address address={section.virtual_range.start} dispatch={dispatch} />
                    </td>
                    <td>
                        <Address address={section.virtual_range.end} dispatch={dispatch} />
                    </td>
                    <td>
                        <Size size={section.virtual_range.size} />
                    </td>
                </tr>
            ))}
        </tbody>
    </table>
);

const FunctionsView = ({ ws, dispatch }: { ws: Workspace } & Dispatches) => (
    <div style={{ height: "100%", width: "100%", overflowY: "scroll", overflowX: "scroll" }}>
        <ul>
            {ws.functions.map((f: BigInt) => (
                <li key={f.toString()}>
                    <Address address={f} dispatch={dispatch} />
                </li>
            ))}
        </ul>
    </div>
);

const StringsView = ({ ws, dispatch }: { ws: Workspace } & Dispatches) => (
    <div style={{ height: "100%", width: "100%", overflowY: "scroll", overflowX: "scroll", whiteSpace: "nowrap" }}>
        <table>
            <thead>
                <tr>
                    <th>type</th>
                    <th>address</th>
                    <th>string</th>
                </tr>
            </thead>
            <tbody>
                {ws.strings.map((string: Lancelot.String) => (
                    <tr key={string.address.toString()}>
                        <td>
                            <Address address={string.address} dispatch={dispatch} />
                        </td>
                        <td className="bp4-monospace-text">{string.encoding}</td>
                        <td className="bp4-monospace-text">{string.string}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

function align(number: bigint, alignment: bigint): bigint {
    if (number % alignment !== BigInt(0x0)) {
        return number - (number % alignment);
    } else {
        return number;
    }
}

interface IAppContext {
    ws: Workspace;
    address: address;
    dispatch: any;
}

const AppContext = React.createContext({} as IAppContext);

const AppPage = ({ version, ws }: { version: string; ws: Workspace }) => {
    let address = useSelector<AppState, address>((state) => state.address);
    const dispatch = useDispatch();
    if (address === BigInt(0)) {
        address = ws.pe.base_address;
        dispatch(actions.set_address(ws.pe.base_address));
    }

    const [show_omnibar, set_show_omnibar] = React.useState(false);
    const open_omnibar = useCallback(() => set_show_omnibar(true), [set_show_omnibar]);
    const close_omnibar = useCallback(() => set_show_omnibar(false), [set_show_omnibar]);

    const history = useSelector<AppState, address[]>((state) => state.address_history);
    const hotkeys = useMemo(
        () => [
            {
                combo: "escape",
                global: true,
                label: "pop history",
                onKeyDown: () => dispatch(actions.pop_history()),
            },
            {
                combo: "alt + g",
                global: true,
                label: "show go dialog",
                onKeyDown: open_omnibar,
                preventDefault: true,
            },
        ],
        [dispatch, set_show_omnibar]
    );

    const locations: Location[] = [];
    ws.functions.forEach((address) => {
        locations.push({ type: "function", address: address as bigint });
    });
    ws.sections.forEach((section: Lancelot.Section) => {
        locations.push({ type: "section", address: section.virtual_range.start as bigint, name: section.name });
    });
    ws.strings.forEach((string: Lancelot.String) => {
        locations.push({
            type: "string/" + string.encoding,
            address: string.address as bigint,
            name: string.string.slice(0, 16),
        });
    });
    // TODO: other types of names, like exports, imports, ...

    const onNavigateLocation = useCallback(
        (loc: Location) => {
            if (loc.address !== undefined) {
                close_omnibar();
                dispatch(actions.set_address(loc.address));
            } else {
                throw new Error("unimplemented: location always needs an address");
            }
        },
        [close_omnibar, dispatch]
    );

    const defaultLayout = {
        dockbox: {
            mode: "horizontal" as DockMode,
            children: [
                {
                    mode: "vertical" as DockMode,
                    children: [
                        {
                            tabs: [
                                {
                                    id: "tab-functions",
                                    title: "functions",
                                    content: (
                                        <AppContext.Consumer>
                                            {({ ws, dispatch }) => <FunctionsView ws={ws} dispatch={dispatch} />}
                                        </AppContext.Consumer>
                                    ),
                                },
                                //{id: 'tab-exports', title: 'exports', content: <div>exports</div>},
                                //{id: 'tab-imports', title: 'imports', content: <div>imports</div>},
                                {
                                    id: "tab-strings",
                                    title: "strings",
                                    content: (
                                        <AppContext.Consumer>
                                            {({ ws, dispatch }) => <StringsView ws={ws} dispatch={dispatch} />}
                                        </AppContext.Consumer>
                                    ),
                                },
                            ],
                            size: 1000,
                        },
                        {
                            tabs: [
                                {
                                    id: "tab-sections",
                                    title: "sections",
                                    content: (
                                        <AppContext.Consumer>
                                            {({ ws, dispatch }) => <SectionsView ws={ws} dispatch={dispatch} />}
                                        </AppContext.Consumer>
                                    ),
                                },
                            ],
                            size: 300,
                        },
                    ],
                    size: 300,
                },
                {
                    mode: "horizontal" as DockMode,
                    children: [
                        {
                            panelLock: { panelStyle: "main" },
                            tabs: [
                                {
                                    id: "tab-graph",
                                    title: "graph",
                                    content: (
                                        <AppContext.Consumer>
                                            {({ ws, address, dispatch }) => (
                                                <GraphView ws={ws} address={address} dispatch={dispatch} />
                                            )}
                                        </AppContext.Consumer>
                                    ),
                                },

                                {
                                    id: "tab-disassembly",
                                    title: "disassembly",
                                    content: (
                                        <AppContext.Consumer>
                                            {({ ws, address, dispatch }) => (
                                                <DisassemblyView ws={ws} address={address} dispatch={dispatch} />
                                            )}
                                        </AppContext.Consumer>
                                    ),
                                },
                            ],
                        },
                    ],
                    size: 1000,
                },
                {
                    mode: "horizontal" as DockMode,
                    children: [
                        {
                            tabs: [
                                {
                                    id: "tab-hex",
                                    title: "hex",
                                    content: (
                                        <AppContext.Consumer>
                                            {({ ws, address, dispatch }) => (
                                                <HexView ws={ws} address={address} dispatch={dispatch} />
                                            )}
                                        </AppContext.Consumer>
                                    ),
                                    // HACK: empirical
                                    minWidth: 640,
                                },
                                {
                                    id: "tab-help",
                                    title: "help",
                                    content: (
                                        <ul>
                                            <li>
                                                <code>alt-g</code> to open the goto menu (functions, names, strings,
                                                etc.)
                                            </li>
                                            <li>
                                                <code>esc</code> to go back
                                            </li>
                                        </ul>
                                    ),
                                },
                            ],
                        },
                    ],
                },
            ],
        },
    };

    return (
        <AppContext.Provider value={{ ws, address, dispatch }}>
            <HotkeysProvider>
                <HotkeysTarget2 hotkeys={hotkeys}>
                    <div id="app">
                        <div>
                            <LocationOmnibar
                                isOpen={show_omnibar}
                                locations={locations}
                                onClose={close_omnibar}
                                onItemSelect={onNavigateLocation}
                            />

                            <p>
                                lancelot version: {version} input size: <Size size={ws.buf.length} /> input arch:{" "}
                                {ws.arch}
                            </p>

                            <div>
                                <DockLayout
                                    defaultLayout={defaultLayout}
                                    style={{
                                        position: "absolute",
                                        top: "30px",
                                        bottom: "5px",
                                        left: "5px",
                                        right: "5px",
                                    }}
                                />
                            </div>
                        </div>
                    </div>
                </HotkeysTarget2>
            </HotkeysProvider>
        </AppContext.Provider>
    );
};

// convert the given object from a wasm-allocated object to
// a real JS object. then, free the wasm-allocated object.
//
// only works with plain old data, no methods.
// relies on the fact that wasm-bindgen emits only getters
// for accessing struct data.
//
// the assumes the given object is either:
//  - a wasm-bindgen created object (e.g. with .ptr), or
//  - a list of wasm-bindgen created objects.
function wasm_to_js<T>(obj: T): T {
    if (Array.isArray(obj)) {
        return obj.map(wasm_to_js) as any as T;
    } else {
        const obj_ = obj as any;
        const ret: any = {};
        for (const [name, desc] of Object.entries(Object.getOwnPropertyDescriptors(Object.getPrototypeOf(obj)))) {
            if (desc.get !== undefined) {
                // wasm-bindgen emits only getters to access struct data.
                // so we can ignore all other fields (constructor, free, etc.)
                let v = obj_[name];

                if (Object.hasOwnProperty.call(v, "ptr")) {
                    // is a wasm-bindgen object.
                    // recursively convert to JS.
                    v = wasm_to_js(v);
                } else if (Array.isArray(v) && v.length > 0 && Object.hasOwnProperty.call(v[0], "ptr")) {
                    // is a list of wasm-bindgen objects.
                    // recursively convert to JS.
                    v = wasm_to_js(v);
                }

                ret[name] = v;
            }
        }
        obj_.free();
        return ret;
    }
}

// fixup the PE instance to return JS objects
// rather than wasm-allocated objects.
//
// notably, the wasm memory for these objects is immediately free'd,
// rather than JS having to track when to .free() each object.
//
// alternatively, we could have used serde to construct objects via JSON,
// but u64 is translated to BigInt, which isn't supported by JSON.
//
// or, we could use #[wasm_bindgen(inspectable)] and .toJSON(),
// but this doesn't apply recusively, see:
// https://github.com/rustwasm/wasm-bindgen/issues/2292
function pe_from_bytes(buf: Uint8Array): Lancelot.PE {
    const proxy: any = {
        get: function (target: Lancelot.PE, prop: string) {
            if (prop === "sections") {
                return wasm_to_js(target.sections);
            } else if (prop === "strings" || prop === "layout" || prop === "read_insn") {
                const orig = (target as any)[prop];
                return function (...args: any) {
                    // separated out here so we can log during dev.
                    const v1 = orig.apply(target, args);
                    const v2 = wasm_to_js(v1);
                    return v2;
                };
            } else {
                return (target as any)[prop];
            }
        },
    };

    const pe = new Proxy(Lancelot.from_bytes(buf), proxy);
    return pe;
}

async function amain() {
    await init();
    console.log("lancelot: version: ", Lancelot.version());

    APP.set_theme(Settings.get("theme", "light"));

    const buf = Uint8Array.from(NOP.data);
    const pe = pe_from_bytes(buf);

    const layout = pe.layout();

    const bb_by_address: Map<bigint, Lancelot.BasicBlock> = new Map();
    const bbs_by_insn: Map<bigint, bigint[]> = new Map();
    const functions_by_bb: Map<bigint, bigint[]> = new Map();

    for (const [fva, f] of layout.functions.entries()) {
        for (const bb of f.basic_blocks) {
            if (!functions_by_bb.has(bb.address)) {
                functions_by_bb.set(bb.address, []);
            }

            functions_by_bb.get(bb.address)?.push(fva);
            bb_by_address.set(bb.address, bb);

            for (const insnva of bb.instructions) {
                if (!bbs_by_insn.has(insnva)) {
                    bbs_by_insn.set(insnva, []);
                }

                bbs_by_insn.get(insnva)?.push(bb.address);
            }
        }
    }

    const ws: Workspace = {
        buf,
        pe,
        arch: pe.arch,
        functions: Array.prototype.map.call(pe.functions(), BigInt) as address[],
        sections: pe.sections,
        strings: pe.strings(),
        layout: layout,
        // TODO: put call graph here

        // TODO: maybe put this in layout
        bb_by_address,
        bbs_by_insn,
        functions_by_bb,
    };

    const app = (
        <Provider store={store}>
            <AppPage version={Lancelot.version()} ws={ws} />
        </Provider>
    );
    ReactDOM.render(app, document.getElementById("app"));

    Metrics.report(`lancelot/load`, {
        app: "lancelot",
        action: "load",
        version: Lancelot.version(),
    });
}

Utils.docReady(function () {
    console.log("hello world");
    amain()
        .then(() => console.log("goodbye world"))
        .catch((e: any) => console.log("lancelot: error: ", e));
});
