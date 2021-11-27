import { VFS } from "./vfs";

export function get(name: string, _default: any) {
    const vfs = new VFS();
    const key = `setting/${name}`;
    const result = vfs.load(key);
    return result !== null ? result : _default;
}

export function set(name: string, value: any) {
    console.log("lancelot: settings: set:", name);
    const vfs = new VFS();
    const key = `setting/${name}`;
    vfs.save(key, value);
}
