import * as assert from "assert";
import { describe, it } from "mocha";

describe("testing", function () {
    describe("#foo()", function () {
        it("foo is foo", function () {
            assert("foo" === "foo");
        });
    });
});
