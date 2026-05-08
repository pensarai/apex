import { describe, expect, it } from "vitest";
import { transformScriptToFunction } from "./playwrightMcp";

describe("transformScriptToFunction", () => {
  describe("plain expressions", () => {
    it("wraps simple expression in arrow function", () => {
      expect(transformScriptToFunction("document.cookie")).toBe(
        "() => (document.cookie)",
      );
    });

    it("wraps complex expression", () => {
      expect(transformScriptToFunction("localStorage.getItem('token')")).toBe(
        "() => (localStorage.getItem('token'))",
      );
    });

    it("handles expression with whitespace", () => {
      expect(transformScriptToFunction("  document.title  ")).toBe(
        "() => (  document.title  )",
      );
    });
  });

  describe("function expressions", () => {
    it("passes through arrow function", () => {
      const fn = "() => document.cookie";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through arrow function with body", () => {
      const fn = "() => { return document.cookie; }";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through async arrow function", () => {
      const fn = "async () => fetch('/api')";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through function expression", () => {
      const fn = "function() { return document.cookie; }";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through async function expression", () => {
      const fn = "async function() { return await fetch('/api'); }";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("handles arrow function with parameters", () => {
      const fn = "(a, b) => a + b";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });
  });

  describe("IIFEs", () => {
    it("extracts function from simple arrow IIFE", () => {
      const iife = "(() => document.cookie)()";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });

    it("extracts function from arrow IIFE with body", () => {
      const iife = `(() => {
  const tokens = {};
  return tokens;
})()`;
      const expected = `() => {
  const tokens = {};
  return tokens;
}`;
      expect(transformScriptToFunction(iife)).toBe(expected);
    });

    it("extracts function from complex arrow IIFE (from bug report)", () => {
      const iife = `(() => {
  const tokens = {};
  const keys = ['token', 'access_token', 'accessToken', 'auth_token', 'jwt', 'id_token'];
  keys.forEach(key => {
    const lsVal = localStorage.getItem(key);
    const ssVal = sessionStorage.getItem(key);
    if (lsVal) tokens[key + '_localStorage'] = lsVal;
    if (ssVal) tokens[key + '_sessionStorage'] = ssVal;
  });
  return JSON.stringify(tokens, null, 2);
})()
`;
      const result = transformScriptToFunction(iife);
      expect(result).toContain("() => {");
      expect(result).toContain("const tokens = {};");
      expect(result).toContain("return JSON.stringify(tokens, null, 2);");
      expect(result).not.toContain(")()");
    });

    it("extracts function from async arrow IIFE", () => {
      const iife = "(async () => await fetch('/api'))()";
      expect(transformScriptToFunction(iife)).toBe(
        "async () => await fetch('/api')",
      );
    });

    it("extracts function from function IIFE", () => {
      const iife = "(function() { return document.cookie; })()";
      expect(transformScriptToFunction(iife)).toBe(
        "function() { return document.cookie; }",
      );
    });

    it("extracts function from async function IIFE", () => {
      const iife = "(async function() { return await fetch('/api'); })()";
      expect(transformScriptToFunction(iife)).toBe(
        "async function() { return await fetch('/api'); }",
      );
    });

    it("handles IIFE with trailing semicolon", () => {
      const iife = "(() => document.cookie)();";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });

    it("handles IIFE with whitespace in invocation", () => {
      const iife = "(() => document.cookie)(  )";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });

    it("handles IIFE with trailing whitespace", () => {
      const iife = "(() => document.cookie)()   ";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });
  });

  describe("edge cases", () => {
    it("handles function that returns a function call", () => {
      const fn = "() => doSomething()";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("does not mis-identify function call as IIFE", () => {
      const expr = "myFunction()";
      expect(transformScriptToFunction(expr)).toBe("() => (myFunction())");
    });

    it("handles JSON stringify in expression", () => {
      const expr = "JSON.stringify({a: 1})";
      expect(transformScriptToFunction(expr)).toBe(
        "() => (JSON.stringify({a: 1}))",
      );
    });

    it("handles empty parentheses expression", () => {
      const expr = "()";
      expect(transformScriptToFunction(expr)).toBe("()");
    });
  });
});
