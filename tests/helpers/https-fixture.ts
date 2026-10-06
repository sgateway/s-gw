import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";

export async function httpsFixture(directory: string) {
  const keyFile = path.join(directory, "server.key");
  const certFile = path.join(directory, "server.crt");
  const command = process.platform === "win32" ? path.join(process.env.ProgramFiles || "C:\\Program Files", "Git", "usr", "bin", "openssl.exe") : "openssl";
  execFileSync(command, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile, "-out", certFile,
    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"], { stdio: "ignore" });
  return { key: await readFile(keyFile, "utf8"), cert: await readFile(certFile, "utf8"), certFile };
}
