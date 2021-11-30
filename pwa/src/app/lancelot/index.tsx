import React, { useCallback, useState } from "react";
import ReactDOM from "react-dom";
import { configureStore, createSlice, Dispatch } from "@reduxjs/toolkit";
import { Provider, useSelector, useDispatch } from "react-redux";

import * as Utils from "../../components/utils";
import * as Settings from "../../components/settings";
import * as Metrics from "../../components/metrics";

import init, * as Lancelot from "../../../../jslancelot/pkg/jslancelot";
import NOP from "./nop.bin";

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
}

export const { actions, reducer } = createSlice({
    name: "app",
    initialState: {
        address: BigInt(0x400000),
    },
    reducers: {
        set_address: (state, action) => {
            state.address = action.payload;
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
    pe: Lancelot.PE;
}

const HexView = (props: { ws: Workspace; address: address; size?: number } & Dispatches) => {
    const { address, ws, size = 0x100 } = props;
    const { dispatch } = props;
    const buf = ws.pe.read_bytes(address, size);

    return (
        <div className="lancelot-hex-view">
            <p>
                hex@
                <Address address={address} dispatch={dispatch} />:
            </p>
            <pre>{Utils.hexdump(buf, address as bigint)}</pre>
        </div>
    );
};

const DisassemblyView = (props: { ws: Workspace; address: address; size?: number } & Dispatches) => {
    const { address, ws, size = 0x100 } = props;
    const { dispatch } = props;

    const insns = [];
    let insn_address = address;
    let error: any = null;
    while (insn_address < (address as bigint) + BigInt(size)) {
        try {
            const insn = ws.pe.read_insn(insn_address);
            insns.push(insn);

            console.log(insn);

            (insn_address as bigint) += BigInt(insn.size);
        } catch (err) {
            error = err;
            break;
        }
    }

    return (
        <div className="lancelot-disassembly-view">
            <p>
                disassembly@
                <Address address={address} dispatch={dispatch} />:
            </p>
            <div>
                {insns.map((insn) => (
                    <React.Fragment key={insn.address.toString()}>
                        <span>
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

const AppPage = ({ version, ws }: { version: string; ws: Workspace }) => {
    const address = useSelector<AppState, address>((state) => state.address);
    const dispatch = useDispatch();

    return (
        <div id="app">
            <header style={{ padding: "8px" }}>
                <nav>lancelot version: {version}</nav>
            </header>
            <div style={{ padding: "8px" }}>
                <p>
                    size: <Size size={ws.buf.length} />
                </p>

                <p>arch: {ws.arch}</p>

                <HexView ws={ws} address={address} dispatch={dispatch} />
                <DisassemblyView ws={ws} address={address} dispatch={dispatch} />

                <p>sections:</p>

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
                        {Array.prototype.map.call(ws.sections, (section: Lancelot.Section) => (
                            <tr key={section.name}>
                                <td>
                                    <NamedLocation
                                        name={section.name}
                                        address={section.virtual_range.start}
                                        dispatch={dispatch}
                                    />
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

                <p>functions:</p>

                <ul>
                    {Array.prototype.map.call(ws.functions, (f: BigInt) => (
                        <li key={f.toString()}>
                            <Address address={f} dispatch={dispatch} />
                        </li>
                    ))}
                </ul>
            </div>
        </div>
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
                    // is a wasm-bindgen object
                    // recursively convert to JS.
                    v = wasm_to_js(v);
                }

                // TODO: handle lists

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
            } else if (prop === "read_insn") {
                const orig = (target as any)[prop];
                return function(...args: any) {
                    return wasm_to_js(orig.apply(target, args));
                }
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

    const ws: Workspace = {
        buf,
        pe,
        arch: pe.arch,
        functions: Array.prototype.map.call(pe.functions(), BigInt) as address[],
        sections: pe.sections,
    };

    const app = (
        <Provider store={store}>
            <AppPage version={Lancelot.version()} ws={ws} />;
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
