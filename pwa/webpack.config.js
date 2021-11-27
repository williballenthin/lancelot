const path = require("path");
const webpack = require("webpack");

module.exports = {
    entry: {
        lancelot: "./src/app/lancelot/index.ts",
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
                exclude: /node_modules/,
            },
            {
                test: /\.yaml$/,
                type: "json",
                use: "yaml-loader",
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
};
