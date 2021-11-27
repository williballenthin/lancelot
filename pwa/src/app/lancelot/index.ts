import { render } from "preact";
import { html } from "htm/preact";

import { docReady } from "../../components/utils";
import * as Settings from "../../components/settings";
import * as Metrics from "../../components/metrics";

import init, * as Lancelot from "../../../../jslancelot/pkg/jslancelot"
import NOP from "./nop.bin"

export const APP = {
    set_theme: (name: string) => {
        document.getElementsByTagName("html")[0].className = `lancelot-theme-${name}`;
        Settings.set("theme", name);
    },
};

const AppPage = ({version, buf, ws}: any) => html`
    <div id="app">
        <header>
            <nav>version: ${version}</nav>
        </header>
        <div>
            <p>
                size: ${buf.length}
            </p>

            <p>
                arch: ${ws.arch}
            </p>

            <p>
                functions:
                <ul>
                    ${Array.prototype.map.call(ws.functions, (f: BigInt) => html`<li>0x${f.toString(0x10)}</li>`)}
                </ul>
            </p>
        </div>
    </div>
`;

async function amain() {
    await init();
    console.log("lancelot: version: ", Lancelot.version());

    APP.set_theme(Settings.get("theme", "light"));

    const buf = Uint8Array.from(NOP.data);
    const ws = Lancelot.from_bytes(buf);

    render(html` <${AppPage} version=${Lancelot.version()} buf=${buf} ws=${ws} /> `, document.getElementById("app") as Element);

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
