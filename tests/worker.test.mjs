import { describe, it, expect } from "vitest";
import { toBase62, randomCode, validateLongUrl, validateCustomCode, validateExpiry, validateMaxClicks } from "../worker/index.js";

describe("toBase62", () => {
  it("encodes 0", () => expect(toBase62(0)).toBe("0"));
  it("encodes within one digit", () => expect(toBase62(61)).toBe("Z"));
  it("rolls over at 62", () => expect(toBase62(62)).toBe("10"));
  it("encodes the seed id as three chars", () => expect(toBase62(3844)).toBe("100"));
});

describe("validateLongUrl", () => {
  it("accepts a normal https URL", () =>
    expect(validateLongUrl("https://example.com/page?x=1", "short.dev").url).toBe("https://example.com/page?x=1"));
  it("rejects non-http schemes", () =>
    expect(validateLongUrl("ftp://example.com", "short.dev").error).toMatch(/http/));
  it("rejects javascript: URLs", () =>
    expect(validateLongUrl("javascript:alert(1)", "short.dev").error).toBeTruthy());
  it("rejects the shortener's own host (loop guard)", () =>
    expect(validateLongUrl("https://short.dev/abc", "short.dev").error).toMatch(/loop/));
  it("rejects private and local addresses", () => {
    for (const h of ["http://localhost/", "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.1.1/", "http://172.16.0.1/"]) {
      expect(validateLongUrl(h, "short.dev").error).toBeTruthy();
    }
  });
  it("rejects URLs over 2048 chars", () =>
    expect(validateLongUrl("https://example.com/" + "a".repeat(2050), "short.dev").error).toMatch(/too long/));
  it("rejects garbage", () => expect(validateLongUrl("not a url", "short.dev").error).toBeTruthy());
});

describe("validateCustomCode", () => {
  it("accepts letters, numbers, dash and underscore", () =>
    expect(validateCustomCode("my-link_1")).toBeNull());
  it("rejects under 3 chars", () => expect(validateCustomCode("ab").error).toBeTruthy());
  it("rejects reserved route words", () => expect(validateCustomCode("api").error).toMatch(/reserved/));
  it("rejects invalid characters", () => expect(validateCustomCode("a b!").error).toBeTruthy());
});

describe("validateExpiry", () => {
  it("empty means no expiry", () => expect(validateExpiry("").expires_at).toBeNull());
  it("rejects unparseable dates", () => expect(validateExpiry("banana").error).toBeTruthy());
  it("rejects past dates", () => expect(validateExpiry("2020-01-01").error).toMatch(/past/));
  it("accepts a future date", () => {
    const r = validateExpiry("2999-01-01");
    expect(r.error).toBeUndefined();
    expect(r.expires_at).toBe("2999-01-01T00:00:00.000Z");
  });
});


describe("randomCode (unguessable short codes)", () => {
  it("returns 8 base62 characters by default", () => {
    expect(randomCode()).toMatch(/^[0-9a-zA-Z]{8}$/);
  });

  it("honours a custom length", () => {
    expect(randomCode(12)).toHaveLength(12);
  });

  it("does not repeat across many draws", () => {
    const seen = new Set();
    for (let i = 0; i < 500; i++) seen.add(randomCode());
    expect(seen.size).toBe(500);
  });
});

describe("validateMaxClicks", () => {
  it("accepts empty and whole numbers in range", () => {
    expect(validateMaxClicks(undefined).max_clicks).toBeNull();
    expect(validateMaxClicks("").max_clicks).toBeNull();
    expect(validateMaxClicks(1).max_clicks).toBe(1);
    expect(validateMaxClicks("250").max_clicks).toBe(250);
    expect(validateMaxClicks(1000000).max_clicks).toBe(1000000);
  });
  it("rejects zero, negatives, fractions, non-numbers and huge values", () => {
    for (const bad of [0, -1, 2.5, "abc", 1000001, NaN]) {
      expect(validateMaxClicks(bad).error).toBeTruthy();
    }
  });
});
