export function report(action: string, meta: Record<string, string>) {
    const headers: Record<string, string> = {};

    for (const [k, v] of Object.entries(meta)) {
        headers[`X-Metric-${k}`] = v;
    }

    /*
    fetch("/metrics/" + action, {
        mode: "cors",
        credentials: "include",
        method: "GET",
        headers,
    });
    */
}
