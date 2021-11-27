import { render } from "preact";
import { html } from "htm/preact";

import { docReady } from "../../components/utils";
import * as Settings from "../../components/settings";
import * as Metrics from "../../components/metrics";

export const APP = {
    set_theme: (name: string) => {
        document.getElementsByTagName("html")[0].className = `lancelot-theme-${name}`;
        Settings.set("theme", name);
    },
};

const AppPage = () => html`
    <div id="app">
        <header>
            <nav>nav</nav>
        </header>
        <div>body</div>
    </div>
`;

async function amain() {
    APP.set_theme(Settings.get("theme", "light"));

    render(html` <${AppPage} /> `, document.getElementById("app") as Element);

    Metrics.report(`lancelot/load`, {
        app: "lancelot",
        action: "load",
    });
}

docReady(function () {
    console.log("hello world");
    amain()
        .then(() => console.log("goodbye world"))
        .catch((e: any) => console.log("lancelot: error: ", e));
});
