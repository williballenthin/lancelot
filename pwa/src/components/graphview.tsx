import React from "react";
import * as dagre from "dagre";

import * as lancelot from "../../../jslancelot/pkg/jslancelot";
import * as utils from "./utils";

import { Workspace, address, Address } from "./common";
import { Dispatches } from "./store";

export class Pannable extends React.Component<{ children: JSX.Element | null }, any> {
    foreground_ref: React.RefObject<any>;
    background_ref: React.RefObject<any>;

    constructor(props: any) {
        super(props);
        this.foreground_ref = React.createRef();
        this.background_ref = React.createRef();
    }

    render() {
        return (
            <div ref={this.background_ref} style={{ width: "100%", height: "100%" }}>
                <div ref={this.foreground_ref} style={{ width: "100%", height: "100%" }}>
                    {this.props.children}
                </div>
            </div>
        );
    }

    componentDidMount() {
        // via: https://codepen.io/loxks/details/KKpVvVW
        let isDown = false;

        // the position of the cursor at the start of a drag.
        let startX = 0;
        let startY = 0;

        // the position of the foreground at the start of a drag.
        // this is updated when a drag completes.
        let x = 0;
        let y = 0;

        let velX = 0;
        let velY = 0;

        // TODO: enable scrolling
        // TODO: enable touch interactions

        this.background_ref.current.addEventListener("mousedown", (e: MouseEvent) => {
            isDown = true;
            this.background_ref.current.classList.add("active");
            this.background_ref.current.style.userSelect = "none";
            // TODO: style: set cursor: grabbing

            startX = e.pageX;
            startY = e.pageY;
            cancelMomentumTracking();
        });

        const finish_drag = (e: MouseEvent) => {
            isDown = false;
            this.background_ref.current.classList.remove("active");

            const dx = e.pageX - startX;
            const dy = e.pageY - startY;

            y = y + dy;
            x = x + dx;
        };

        this.background_ref.current.addEventListener("mouseleave", (e: MouseEvent) => {
            if (!isDown) {
                return;
            }

            finish_drag(e);
            beginMomentumTracking();
        });

        this.background_ref.current.addEventListener("mouseup", (e: MouseEvent) => {
            finish_drag(e);
            beginMomentumTracking();
        });

        // the position of the cursor at the last mousemove event
        let lastX = 0;
        let lastY = 0;

        this.background_ref.current.addEventListener("mousemove", (e: MouseEvent) => {
            if (!isDown) {
                return;
            }
            e.preventDefault();

            const dx = e.pageX - startX;
            const dy = e.pageY - startY;

            this.foreground_ref.current.style.transform = `translateX(${x + dx}px) translateY(${y + dy}px)`;

            velX = e.pageX - lastX;
            velY = e.pageY - lastY;

            lastX = e.pageX;
            lastY = e.pageY;
        });

        // Momentum

        let momentumID = 0;
        function beginMomentumTracking() {
            cancelMomentumTracking();
            momentumID = requestAnimationFrame(momentumLoop);
        }

        function cancelMomentumTracking() {
            cancelAnimationFrame(momentumID);
        }

        const momentumLoop = () => {
            x += velX;
            y += velY;

            this.foreground_ref.current.style.transform = `translateX(${x}px) translateY(${y}px)`;

            velX *= 0.9;
            velY *= 0.9;

            if (Math.abs(velX) > 0.5 || Math.abs(velY) > 0.5) {
                momentumID = requestAnimationFrame(momentumLoop);
            }
        };
    }

    componentWillUnmount() {
        // TODO: detach handlers
    }
}

function graph_with_defaults(): dagre.graphlib.Graph {
    const g = new dagre.graphlib.Graph();

    g.setGraph({
        // Direction for rank nodes.
        // Can be TB, BT, LR, or RL, where T = top, B = bottom, L = left, and R = right.
        // default: TB
        rankdir: "TB",
        // Alignment for rank nodes.
        // Can be UL, UR, DL, or DR, where U = up, D = down, L = left, and R = right.
        // default: undefined
        align: "UL",
        // Number of pixels that separate nodes horizontally in the layout.
        // default: 50
        nodesep: 50,
        // Number of pixels that separate edges horizontally in the layout.
        // default: 10
        edgesep: 10,
        // Number of pixels between each rank in the layout.
        // default: 50
        ranksep: 50,
        // Number of pixels to use as a margin around the left and right of the graph.
        // default: 0
        marginx: 100,
        // Number of pixels to use as a margin around the top and bottom of the graph.
        // default: 0
        marginy: 100,
        // If set to greedy, uses a greedy heuristic for finding a feedback arc set for a graph.
        // A feedback arc set is a set of edges that can be removed to make a graph acyclic.
        // default: undefined
        acyclicer: undefined,
        // Type of algorithm to assigns a rank to each node in the input graph.
        // Possible values: network-simplex, tight-tree or longest-path
        // default: network-simplex
        ranker: "network-simplex",
    });

    g.setDefaultEdgeLabel(function () {
        return {};
    });

    return g;
}

/* determined empirically, units: pixels */
const LINE_HEIGHT = 18;
const CHARACTER_WIDTH = 8.9;

function graph_add_basic_block(ws: Workspace, g: dagre.graphlib.Graph, bb: lancelot.BasicBlock) {
    const height_in_lines = bb.instructions.length;
    const insns: lancelot.Instruction[] = Array.from(bb.instructions).map(ws.pe.read_insn);
    // max instruction length in bytes
    // used for computing padding of hex column
    const max_insn_len = Math.max(...insns.map((insn) => insn.bytes.length));
    // plaintext representation of each line.
    // NB: keep this in sync with pretty line rendering.
    const lines: string[] = insns.map((insn) => {
        const hex = Array.from(insn.bytes)
            .map((b) => utils.RENDERED_HEX[b])
            .join("")
            .padEnd(max_insn_len * 2, " ");
        return `0x${insn.address.toString(0x10)}  ${hex}  ${insn.string}`;
    });
    const width_in_characters = Math.max(...lines.map((line) => line.length));

    g.setNode(bb.address.toString(0x10), {
        // node properties:
        //
        // width, default:0
        // The width of the node in pixels.
        //
        // height, default: 0
        // The height of the node in pixels.
        height: height_in_lines * LINE_HEIGHT,
        width: width_in_characters * CHARACTER_WIDTH,

        insns,
        lines,
        max_insn_len,
    });
}

function graph_add_edge(g: dagre.graphlib.Graph, bb: lancelot.BasicBlock, flow: lancelot.Flow) {
    g.setEdge(bb.address.toString(0x10), flow.target[1].toString(0x10), {
        // edge properties:
        //
        // minlen, default: 1
        // The number of ranks to keep between the source and target of the edge.
        //
        // weight, default: 1
        // The weight to assign edges. Higher weight edges are generally made shorter and straighter than lower weight edges.
        //
        // width, default: 0
        // The width of the edge label in pixels.
        //
        // height, default: 0
        // The height of the edge label in pixels.
        //
        // labelpos, default: r
        // Where to place the label relative to the edge. l = left, c = center r = right.
        //
        // labeloffset, default: 10
        // How many pixels to move the label away from the edge. Applies only when labelpos is l or r.
        weight: flow.type === "fallthrough" ? 1 : 0.5,
        minlen: 1,
        width: 0,
        height: 0,
        labelpos: "r",
        labeloffset: 10,

        type: flow.type,
    });
}

function graph_from_blocks(ws: Workspace, basic_blocks: lancelot.BasicBlock[]): dagre.graphlib.Graph {
    const g = graph_with_defaults();
    basic_blocks.forEach((bb: lancelot.BasicBlock) => {
        graph_add_basic_block(ws, g, bb);
        bb.successors.forEach((succ: lancelot.Flow) => {
            if (succ.type !== "call") {
                graph_add_edge(g, bb, succ);
            }
        });
    });
    dagre.layout(g);
    return g;
}

interface Point {
    x: number;
    y: number;
}

const Line = (props: { p1: Point; p2: Point; thickness?: number; className: string }) => {
    const { p1, p2, className } = props;
    let { thickness } = props;
    if (!thickness) {
        thickness = 1;
    }

    const length = Math.sqrt((p2.x - p1.x) * (p2.x - p1.x) + (p2.y - p1.y) * (p2.y - p1.y));
    const cx = (p1.x + p2.x) / 2 - length / 2;
    const cy = (p1.y + p2.y) / 2 - thickness / 2;
    const angle = Math.atan2(p1.y - p2.y, p1.x - p2.x) * (180 / Math.PI);

    return (
        <div
            className={className}
            style={{
                padding: "0px",
                margin: "0px",
                height: `${thickness}px`,
                lineHeight: "1px",
                position: "absolute",
                left: `${cx}px`,
                top: `${cy}px`,
                width: `${length}px`,
                transform: `rotate(${angle}deg)`,
                zIndex: 0,
            }}
        />
    );
};

const Edge = (props: { points: Point[]; className: string }): JSX.Element[] => {
    const { points, className } = props;
    const ret = [];
    for (let i = 0; i < points.length - 1; i++) {
        const p1 = points[i];
        const p2 = points[i + 1];
        ret.push(<Line p1={p1} p2={p2} className={className} />);
    }
    return ret;
};

const Node = ({ node, dispatch }: { node: any } & Dispatches) => (
    <div
        style={{
            height: node.height + 1 /* border width */,
            width: node.width + 1 /* border width */ + 6 /* padding */,
            position: "absolute",
            top: node.y - node.height / 2,
            left: node.x - node.width / 2,
            backgroundColor: "white",
            border: "1px solid blue",
            boxShadow: "0px 0px 4px 2px rgba(128, 128, 128, .2)",

            paddingLeft: "3px",
            paddingRight: "3px",

            // place BB boxes (z-index 1) over lines for edges (z-index 0)
            zIndex: 1,
        }}
    >
        {(node as any).insns.map((insn: lancelot.Instruction) => {
            // like: EBFE
            const hex_column = Array.from(insn.bytes)
                .map((b) => utils.RENDERED_HEX[b])
                .join("")
                .padEnd((node as any).max_insn_len * 2, " ");

            return (
                <span
                    className="bp4-monospace-text"
                    style={{ display: "inline-block", width: "100%", whiteSpace: "pre" }}
                    key={insn.address.toString(0x10)}
                >
                    <Address address={insn.address} dispatch={dispatch} />{" "}
                    <span style={{ color: "gray" }}>{hex_column}</span>{" "}
                    <span style={{ color: "black" }}>{insn.string}</span>
                </span>
            );
        })}
    </div>
);

const INVALID_GRAPH = (
    <div className="lancelot-graph-view" style={{ height: "100%", width: "100%" }}>
        <p>no function graph</p>
    </div>
);

export const GraphView = (props: { ws: Workspace; address: address; size?: number } & Dispatches) => {
    const { address, ws } = props;
    const { dispatch } = props;

    const bbva = ws.blocks_by_insn.get(address as bigint);
    if (bbva === undefined) {
        console.log("block not found: " + address.toString(0x10));
        return INVALID_GRAPH;
    }

    const blocks = Array.from(ws.cfg.get_reachable_blocks(bbva)).map((bbva) => {
        // TODO: better typing
        return ws.cfg.basic_blocks.get(bbva) as lancelot.BasicBlock;
    });

    const g = graph_from_blocks(ws, blocks);
    const elems: JSX.Element[] = [];

    g.nodes().forEach(function (v) {
        if (g.node(v) === undefined) {
            console.log("empty node", v);
        } else {
            elems.push(<Node node={g.node(v)} dispatch={dispatch} />);
        }
    });

    g.edges().forEach(function (e) {
        const edge = g.edge(e);
        const classes = `edge edge-${(edge as any).type.replace(" ", "-")}`;
        elems.push(...Edge({ points: edge.points, className: classes }));
    });

    return (
        <div className="lancelot-graph-view" style={{ height: "100%", width: "100%" }}>
            <Pannable>
                <div>{...elems}</div>
            </Pannable>
        </div>
    );
};
