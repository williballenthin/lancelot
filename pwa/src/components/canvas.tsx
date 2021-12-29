import React from "react";

export class Canvas extends React.Component<{ children: JSX.Element | null }, any> {
    foreground_ref: React.RefObject<any>;
    background_ref: React.RefObject<any>;

    is_mouse_down: boolean;

    constructor(props: any) {
        super(props);
        this.foreground_ref = React.createRef();
        this.background_ref = React.createRef();

        this.is_mouse_down = false;
    }

    render() {
        return (
            <div ref={this.background_ref} style={{ width: "100%", height: "100%", cursor: "grab" }}>
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
