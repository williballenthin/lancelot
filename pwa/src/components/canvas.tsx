import React from "react";
import * as dagre from "dagre";

export class Canvas extends React.Component<{ children: JSX.Element | null }, any> {
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

export function layout_graph() {
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

    // node properties:
    //
    // width, default:0
    // The width of the node in pixels.
    //
    // height, default: 0
    // The height of the node in pixels.
    g.setNode("kspacey", { label: "Kevin Spacey", width: 144, height: 100 });
    g.setNode("swilliams", { label: "Saul Williams", width: 160, height: 100 });
    g.setNode("bpitt", { label: "Brad Pitt", width: 108, height: 100 });
    g.setNode("hford", { label: "Harrison Ford", width: 168, height: 100 });
    g.setNode("lwilson", { label: "Luke Wilson", width: 144, height: 100 });
    g.setNode("kbacon", { label: "Kevin Bacon", width: 121, height: 100 });

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
    g.setEdge("kspacey", "swilliams");
    g.setEdge("swilliams", "kbacon");
    g.setEdge("bpitt", "kbacon");
    g.setEdge("hford", "lwilson");
    g.setEdge("lwilson", "kbacon");

    dagre.layout(g);

    const nodes: JSX.Element[] = [];

    g.nodes().forEach(function (v) {
        const node = g.node(v);

        nodes.push(
            <div
                style={{
                    height: node.height,
                    width: node.width,
                    position: "absolute",
                    top: node.y - node.height / 2,
                    left: node.x - node.width / 2,
                    backgroundColor: "gray",
                    border: "3px dashed black",
                }}
            >
                {node.label}
            </div>
        );
    });

    const edges: JSX.Element[] = [];

    g.edges().forEach(function (e) {
        const THICKNESS = 3;
        const edge = g.edge(e);

        for (let i = 0; i < edge.points.length - 1; i++) {
            const p1 = edge.points[i];
            const p2 = edge.points[i + 1];

            const length = Math.sqrt((p2.x - p1.x) * (p2.x - p1.x) + (p2.y - p1.y) * (p2.y - p1.y));
            const cx = (p1.x + p2.x) / 2 - length / 2;
            const cy = (p1.y + p2.y) / 2 - THICKNESS / 2;
            const angle = Math.atan2(p1.y - p2.y, p1.x - p2.x) * (180 / Math.PI);

            edges.push(
                <div
                    style={{
                        padding: "0px",
                        margin: "0px",
                        height: `${THICKNESS}px`,
                        backgroundColor: "gray",
                        lineHeight: "1px",
                        position: "absolute",
                        left: `${cx}px`,
                        top: `${cy}px`,
                        width: `${length}px`,
                        transform: `rotate(${angle}deg)`,
                    }}
                ></div>
            );
        }
    });

    return (
        <div>
            {...nodes}
            {...edges}
        </div>
    );
}