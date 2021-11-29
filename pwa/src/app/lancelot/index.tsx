import ReactDOM from "react-dom";

import { docReady } from "../../components/utils";
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

// an address that may be valid in this workspace.
const Address = ({address} : {address: address}) => (
    <span className="lancelot-address bp4-monospace-text">0x{address.toString(0x10)}</span>
);

// a size of an item or delta/difference between two addresses.
const Size = ({size} : {size: u64}) => (
    <span className="lancelot-size bp4-monospace-text">0x{size.toString(0x10)}</span>
);

// the name of a location for which the address is known.
const NamedLocation = ({name, address} : {name: string, address: address}) => (
    <span className="lancelot-named-location bp4-monospace-text">{name}</span>
);

const AppPage = ({ version, buf, ws, pe }: any) => (
    <div id="app">
        <header style={{padding: "8px"}}>
            <nav>lancelot version: {version}</nav>
        </header>
        <div style={{padding: "8px"}}>
            <p>size: <Size size={buf.length} /></p>

            <p>arch: {ws.arch}</p>

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
                        <td><NamedLocation name={section.name} address={section.virtual_range.start} /></td>
                        <td><Address address={section.virtual_range.start} /></td>
                        <td><Address address={section.virtual_range.end} /></td>
                        <td><Size size={section.virtual_range.size} /></td>
                    </tr>
                ))}
                </tbody>
            </table>

            <p>functions:</p>

            <ul>
                {Array.prototype.map.call(ws.functions, (f: BigInt) => (
                    <li key={f.toString()}><Address address={f} /></li>
                ))}
            </ul>
        </div>
    </div>
);

function to_js<T>(obj: T): T {
    if (Array.isArray(obj)) {
        const ret = obj.map(to_js);
        for (const v in obj) {
            (v as any).free();
        }
        return ret as any as T;
    } else {
        const obj_ = obj as any;
        const ret: any = {};
        for (const [name, desc] of Object.entries(Object.getOwnPropertyDescriptors(Object.getPrototypeOf(obj)))) {
            if (desc.get !== undefined) {
                // is a getter
                let v = obj_[name];

                if (Object.hasOwnProperty.call(v, "ptr")) {
                    // is a wasm-bindgen object
                    // recursively convert to JS.
                    v = to_js(v);
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
function pe_from_bytes(buf: Uint8Array): Lancelot.PE {
    const proxy: any = {
        get: function(target: Lancelot.PE, prop: string) {
            if (prop === "sections") {
                return to_js(target.sections)
            } else {
                return (target as any)[prop];
            }
        }
    }

    const pe = new Proxy(Lancelot.from_bytes(buf), proxy);
    return pe;
}

async function amain() {
    await init();
    console.log("lancelot: version: ", Lancelot.version());

    APP.set_theme(Settings.get("theme", "light"));

    const buf = Uint8Array.from(NOP.data);
    const pe = pe_from_bytes(buf);

    const ws = {
        arch: pe.arch,
        functions: pe.functions(),
        sections: pe.sections,
    }

    const app = <AppPage version={Lancelot.version()} buf={buf} pe={pe} ws={ws} />;

    ReactDOM.render(app, document.getElementById("app"));

    Metrics.report(`lancelot/load`, {
        app: "lancelot",
        action: "load",
        version: Lancelot.version(),
    });
}

docReady(function () {
    console.log("hello world");
    amain()
        .then(() => console.log("goodbye world"))
        .catch((e: any) => console.log("lancelot: error: ", e));
});
