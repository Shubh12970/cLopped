import { describe, it, expect } from "vitest";
import { refererHost } from "../worker/index.js";

describe("refererHost (stats breakdown labels)", () => {
  it("reduces a full URL to its host", () =>
    expect(refererHost("https://x.com/post/1?ref=abc")).toBe("x.com"));
  it("keeps subdomains distinct", () =>
    expect(refererHost("https://m.instagram.com/story")).toBe("m.instagram.com"));
  it("empty referrer means a direct visit", () => expect(refererHost("")).toBe("direct"));
  it("unparseable values fall back to other", () => expect(refererHost("not a url")).toBe("other"));
});
