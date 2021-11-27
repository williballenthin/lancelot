const path = require("path");
const process = require("process");
const webpack = require("webpack");

const isDevelopment = process.env.NODE_ENV !== "production";

module.exports = {
    mode: isDevelopment ? "development" : "production",
    entry: {
        lancelot: "./src/app/lancelot/index.tsx",
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                exclude: /node_modules/,
                loader: "ts-loader",
                /*
                options: {
                    getCustomTransformers: () => ({
                        before: [require('react-refresh-typescript')()]
                    }),
                }
                */
            },
            {
                test: /\.yaml$/,
                type: "json",
                use: "yaml-loader",
            },
            {
                test: /\.bin$/,
                exclude: /node_modules/,
                type: "asset/inline",
                generator: {
                    dataUrl: (content) => {
                        return content;
                    },
                },
            },
        ],
    },
    resolve: {
        extensions: [".tsx", ".ts", ".js", ".yaml"],
        fallback: {
            console: require.resolve("console-browserify"),
        },
    },
    plugins: [
        new webpack.EnvironmentPlugin({
            NODE_DEBUG: false,
        }),
    ],
    output: {
        filename: "[name].bundle.js",
        path: path.resolve(__dirname, "public", "js"),
    },
    devtool: "source-map",
    optimization: {
        // will not emit the bundle in prod mode if *any* error is encountered.
        emitOnErrors: false,
    },
    /*
    devServer: {
        hot: true,
    },
    */
};
