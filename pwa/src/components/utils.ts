// add the given child as the first child in the given element.
export const pushChild = (el: Element, child: Element) => {
    if (el.hasChildNodes()) {
        el.insertBefore(child, el.firstChild);
    } else {
        el.appendChild(child);
    }
};

// from: https://stackoverflow.com/a/9899701/87207
export function docReady(fn: () => void) {
    if (document.readyState === "complete" || document.readyState === "interactive") {
        setTimeout(fn, 1);
    } else {
        document.addEventListener("DOMContentLoaded", fn);
    }
}

// https://javascript.info/cookie#getcookie-name
export function get_cookie(name: string): string | undefined {
    const matches = document.cookie.match(
        new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[]\\\/\+^])/g, "\\$1") + "=([^;]*)")
    );
    return matches ? decodeURIComponent(matches[1]) : undefined;
}

interface CookieOptions {
    expires?: Date | string;
    path?: string;
    secure?: boolean;
    samesite?: string;
    "max-age"?: number;
}

// https://javascript.info/cookie#setcookie-name-value-options
export function set_cookie(name: string, value: string, options: CookieOptions = {}): void {
    options = {
        ...options,
        path: "/",
        secure: true,
        samesite: "strict",
    };

    if (options.expires instanceof Date) {
        options.expires = options.expires.toUTCString();
    }

    let updatedCookie = encodeURIComponent(name) + "=" + encodeURIComponent(value);

    for (const optionKey in options) {
        updatedCookie += "; " + optionKey;
        const optionValue = (options as Record<string, any>)[optionKey];
        if (optionValue !== true) {
            updatedCookie += "=" + optionValue;
        }
    }

    document.cookie = updatedCookie;
}

export function delete_cookie(name: string): void {
    set_cookie(name, "", { expires: "Thu, 01 Jan 1970 00:00:00 UTC" });
}

// from: https://formcarry.com/documentation/fetch-api-example
export const encode_form_data = (data: Record<string, string>): string => {
    return Object.keys(data)
        .map((key) => encodeURIComponent(key) + "=" + encodeURIComponent(data[key]))
        .join("&");
};

// see python's `partition` function.
// split at the first instance of the given separacter, returning [before, sep, after].
// if the separator doesn't exist, return everything in `before`, other elements empty strings.
export function partition(s: string, c: string): [string, string, string] {
    const i = s.indexOf(c);
    if (i === -1) {
        return [s, "", ""];
    } else {
        return [s.substring(0, i), c, s.substring(i + c.length)];
    }
}

export function rpartition(s: string, c: string): [string, string, string] {
    const i = s.lastIndexOf(c);
    if (i === -1) {
        return ["", "", s];
    } else {
        return [s.substring(0, i), c, s.substring(i + c.length)];
    }
}

export function open_tab(url: string) {
    window.open(url, "_blank");
}

export function assert(condition: any, msg?: string): asserts condition {
    if (!condition) {
        throw new Error(msg);
    }
}

const _inserted_stylesheets = new Set();

// this is a function intended to be used as a template literal tag,
// like this:
//
//     css`
//       body { color: red; }
//     `;
//
// it installs the css into the current document on first invocation.
// otherwise, its a nop.
//
// this enables you to colocate styles with elements.
// note: the style is not scoped to any element.
export function css(stylesheet: string) {
    if (!_inserted_stylesheets.has(stylesheet)) {
        const style = document.createElement("style");
        style.type = "text/css";
        style.appendChild(document.createTextNode(stylesheet));
        document.head.appendChild(style);

        _inserted_stylesheets.add(stylesheet);
    }
}

// https://www.typescriptlang.org/docs/handbook/unions-and-intersections.html#union-exhaustiveness-checking
export function assertNever(x: never): never {
    throw new Error("Unexpected object: " + x);
}

// timestamp in UTC.
// like: "2021-06-17T19:50:48.520Z"
export function get_timestamp(): string {
    return new Date().toISOString();
}

export function has_property(object: Record<string, unknown>, key: string): boolean {
    return Object.prototype.hasOwnProperty.call(object, key);
}

const RENDERED_HEX: string[] = [];
for (let i = 0; i < 0x100; i++) {
    RENDERED_HEX.push(i.toString(0x10).padStart(2, "0"));
}

const RENDERED_ASCII: string[] = [];
for (let i = 0; i < 0x100; i++) {
    // " " to "~", which are all the printable ascii characters.
    // does not include tab or newline (which may take more than one column).
    if (i >= 0x20 && i <= 0x7f) {
        RENDERED_ASCII.push(String.fromCharCode(i));
    } else {
        RENDERED_ASCII.push(".");
    }
}

export function hexdump(buf: Uint8Array, address: bigint | number): string {
    const ret = [];
    for (let i = 0; i < buf.length; i += 0x10) {
        const hex: string[] = [];
        const ascii: string[] = [];

        const temporary = buf.slice(i, i + 0x10);
        for (const b of temporary) {
            hex.push(RENDERED_HEX[b]);
            ascii.push(RENDERED_ASCII[b]);
        }

        const addr_prefix = (BigInt(address) + BigInt(i)).toString(0x10).padStart(8, "0");
        const hex_column = hex.join(" ");
        const ascii_column = ascii.join("");

        const line = `${addr_prefix}  ${hex_column}  ${ascii_column}`;
        ret.push(line);
    }
    return ret.join("\n");
}

export function hex(buf: Uint8Array, separator = " "): string {
    const ret: string[] = [];
    buf.forEach((b) => ret.push(RENDERED_HEX[b]));
    return ret.join(separator);
}
