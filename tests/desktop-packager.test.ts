import { describe, expect, it } from "vitest";
import { nativePackageName, packageApp } from "../tools/desktop-packager/index.js";
describe("native desktop packager", () => {
  it("retains every upstream native packaging host", () => {
    for (const arch of ["x64", "arm64"]) {
      expect(nativePackageName("darwin", arch)).toBe(`@crabnebula/packager-darwin-${arch}`);
      for (const musl of [false, true]) expect(nativePackageName("linux", arch, musl)).toBe(`@crabnebula/packager-linux-${arch}-${musl ? "musl" : "gnu"}`);
    }
    for (const arch of ["x64", "arm64", "ia32"]) expect(nativePackageName("win32", arch)).toBe(`@crabnebula/packager-win32-${arch}-msvc`);
    expect(nativePackageName("linux", "arm")).toBe("@crabnebula/packager-linux-arm-gnueabihf");
    expect(() => nativePackageName("unknown", "x64")).toThrow("Unsupported");
  });
  it("loads the native package and returns its configuration error", async () => {
    expect(() => packageApp({})).toThrow(/Could not find the main binary/);
  }, 30_000);
});
