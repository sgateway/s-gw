import { describe, expect, it } from "vitest";
import { linuxListenerRecordMatches, systemdAgentSocketFd } from "../src/linux-activated-socket.js";

const socket = "/run/s-gw/agents/session-123/broker.sock";
const table = [
  "Num       RefCount Protocol Flags    Type St Inode Path",
  `00000000: 00000002 00000000 00010000 0001 01 12345 ${socket}`,
  "00000000: 00000002 00000000 00010000 0001 01 67890 /run/other.sock"
].join("\n");

describe("Linux activated agent sockets", () => {
  it("selects one session descriptor from a systemd service with multiple listeners", () => {
    const env = {
      LISTEN_PID: String(process.pid), LISTEN_FDS: "3",
      LISTEN_FDNAMES: "s-gw-agent-other:s-gw-agent-session-123:s-gw-agent-last"
    };
    expect(systemdAgentSocketFd("session-123", env)).toBe(4);
  });

  it("rejects spoofed, unnamed, duplicate, and oversized descriptor manifests", () => {
    const good = { LISTEN_PID: String(process.pid), LISTEN_FDS: "1",
      LISTEN_FDNAMES: "s-gw-agent-session-123" };
    for (const env of [
      { ...good, LISTEN_PID: String(process.pid + 1) },
      { ...good, LISTEN_FDS: "2" },
      { ...good, LISTEN_FDS: "0" },
      { ...good, LISTEN_FDS: "65" },
      { ...good, LISTEN_FDNAMES: "other" },
      { ...good, LISTEN_FDS: "2", LISTEN_FDNAMES: `${good.LISTEN_FDNAMES}:${good.LISTEN_FDNAMES}` }
    ]) expect(() => systemdAgentSocketFd("session-123", env)).toThrow();
    expect(() => systemdAgentSocketFd("../session", good)).toThrow();
  });

  it("matches only a listening stream FD bound to the exact agent path", () => {
    expect(linuxListenerRecordMatches(table, "12345", socket)).toBe(true);
    expect(linuxListenerRecordMatches(table, "67890", socket)).toBe(false);
    expect(linuxListenerRecordMatches(table, "12345", "/run/s-gw/agents/other/broker.sock")).toBe(false);
    expect(linuxListenerRecordMatches(table.replace("00010000 0001", "00000000 0001"), "12345", socket)).toBe(false);
    expect(linuxListenerRecordMatches(table.replace("00010000 0001", "00010000 0002"), "12345", socket)).toBe(false);
    expect(linuxListenerRecordMatches(table.replace("00010000 0001 01", "00010000 0001 03"), "12345", socket)).toBe(false);
  });
});
