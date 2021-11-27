export class VFS {
    constructor() {
        if (this.get_item("lancelot/vfs/keys") === null) {
            this.set_item("lancelot/vfs/keys", []);
        }
    }

    // JSON blob wrapper for local storage
    set_item(k: string, v: any) {
        window.localStorage.setItem(k, JSON.stringify(v));
    }

    // JSON blob wrapper for local storage
    get_item(k: string) {
        const v = window.localStorage.getItem(k);
        if (v === null) {
            return null;
        }
        return JSON.parse(v);
    }

    // JSON blob wrapper for local storage
    delete_item(k: string) {
        window.localStorage.removeItem(k);
    }

    save(title: string, document: any) {
        const key = `lancelot/vfs/documents/${title}`;
        this.set_item(key, document);

        const keys = this.get_item("lancelot/vfs/keys");
        if (keys.indexOf(title) === -1) {
            keys.push(title);
            this.set_item("lancelot/vfs/keys", keys);
        }
    }

    load(title: string) {
        const keys = this.get_item("lancelot/vfs/keys");
        if (keys.indexOf(title) === -1) {
            return null;
        }

        const key = `lancelot/vfs/documents/${title}`;
        return this.get_item(key);
    }

    delete(title: string) {
        const keys = this.get_item("lancelot/vfs/keys");
        if (keys.indexOf(title) === -1) {
            return null;
        }

        this.set_item(
            "lancelot/vfs/keys",
            keys.filter((key: string) => key !== title)
        );
        this.delete_item(`lancelot/vfs/documents/${title}`);
    }

    list(prefix: string) {
        if (prefix === undefined) {
            return this.get_item("lancelot/vfs/keys");
        } else {
            return this.get_item("lancelot/vfs/keys").filter((title: string) => title.startsWith(prefix));
        }
    }
}
