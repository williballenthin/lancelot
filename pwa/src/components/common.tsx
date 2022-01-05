import * as lancelot from "../../../jslancelot/pkg/jslancelot";
import { actions, Dispatches } from "./store";

// helpers for jslancelot
export type u64 = bigint | BigInt;
export type address = u64;

// an address that may be valid in this workspace.
export const Address = ({ address, dispatch }: { address: address } & Dispatches) => (
    <a className="lancelot-address bp4-monospace-text" onDoubleClick={() => dispatch(actions.set_address(address))}>
        0x{address.toString(0x10)}
    </a>
);

// a size of an item or delta/difference between two addresses.
export const Size = ({ size }: { size: u64 | number }) => (
    <span className="lancelot-size bp4-monospace-text">0x{size.toString(0x10)}</span>
);

// the name of a location for which the address is known.
export const NamedLocation = ({ name, address, dispatch }: { name: string; address: address } & Dispatches) => (
    <a
        className="lancelot-named-location bp4-monospace-text"
        onDoubleClick={() => dispatch(actions.set_address(address))}
    >
        {name}
    </a>
);

// these things should not change.
export interface Workspace {
    buf: Uint8Array;
    arch: string;
    functions: address[];
    sections: lancelot.Section[];
    strings: lancelot.String[];
    cfg: lancelot.CFG;
    pe: lancelot.PE;

    blocks_by_insn: Map<bigint, bigint>;
}
