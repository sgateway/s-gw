import { chmod, copyFile, link, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanTextToOnePassword } from "../src/gateway.js";
import { listOnePasswordSecretReferences, onePasswordStatus } from "../src/onepassword.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
let originalNodeOptions: string | undefined;
const fakeVault = "Example";

function opRef(item: string, field: string): string {
  return `op://${fakeVault}/${item}/${field}`;
}

function fakeOpenAiToken(): string {
  return ["sk", "-proj-", "captured_dummy_1234567890abcdef"].join("");
}

beforeEach(async () => {
  originalNodeOptions = process.env.NODE_OPTIONS;
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-op-test-"));
});

afterEach(async () => {
  delete process.env.SGW_OP_CLI;
  delete process.env.SGW_REAL_OP_PATH;
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  if (originalNodeOptions === undefined) {
    delete process.env.NODE_OPTIONS;
  } else {
    process.env.NODE_OPTIONS = originalNodeOptions;
  }
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe("1Password metadata importer", () => {
  it("uses the real gated op binary for brokered s-gw reads when available", async () => {
    const fakeRealOp = await writeFakeOp();
    process.env.SGW_REAL_OP_PATH = fakeRealOp;

    const status = onePasswordStatus();

    expect(status.available).toBe(true);
    expect(status.command).toBe(fakeRealOp);
    expect(status.version).toBe(process.version);
  });

  it("discovers secret-like fields without returning field values", async () => {
    process.env.SGW_OP_CLI = await writeFakeOp();

    const status = onePasswordStatus();
    expect(status.available).toBe(true);
    expect(status.version).toBe(process.version);

    const refs = await listOnePasswordSecretReferences(fakeVault);
    expect(refs).toHaveLength(2);
    expect(refs.map((ref) => ref.fieldLabel)).toEqual(["credential", "password"]);
    expect(refs.map((ref) => ref.reference)).toEqual([
      opRef("aws-dev", "credential"),
      opRef("github", "password")
    ]);
    expect(refs[0].suggestedEnv).toBe("AWS_SECRET_ACCESS_KEY");
    expect(refs[0].companionFields).toEqual([
      expect.objectContaining({
        fieldLabel: "username",
        reference: opRef("aws-dev", "username"),
        secretType: "access-key",
        suggestedEnv: "AWS_ACCESS_KEY_ID"
      })
    ]);
    expect(JSON.stringify(refs)).not.toContain("plain text note");
  });

  it("captures scanned text into a 1Password-backed handle without storing the raw value locally", async () => {
    process.env.SGW_OP_CLI = await writeFakeOp();
    process.env.SGW_HOME = tmpHome;
    process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "unit-test-passphrase";
    const store = new SecretStore(tmpHome);
    await store.init();

    const rawSecret = fakeOpenAiToken();
    const result = await scanTextToOnePassword(store, `OPENAI_API_KEY=${rawSecret}\n`, {
      vault: fakeVault,
      defaultName: "s-gw test capture",
      source: "unit-test",
      policy: {
        injectEnv: "OPENAI_API_KEY",
        allowedCommands: ["/usr/bin/ssh"]
      }
    });

    expect(result.findings).toHaveLength(1);
    expect(result.tokenizedText).toContain("<<SGW_SECRET:s-gw:api-token:");
    expect(result.tokenizedText).not.toContain(rawSecret);
    expect(JSON.stringify(result)).not.toContain(rawSecret);

    const handles = await store.listHandles();
    expect(handles).toHaveLength(1);
    expect(handles[0].backend).toBe("onepassword");
    expect(handles[0].provider).toBe("1password");
    expect(handles[0].policy.injectEnv).toBe("OPENAI_API_KEY");
    expect(handles[0].policy.allowedCommands).toEqual(["/usr/bin/ssh"]);

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(rawSecret);
    expect(storeText).not.toContain("op://");
  });
});

async function writeFakeOp(): Promise<string> {
  const fakeOp = path.join(tmpHome, process.platform === "win32" ? "op.exe" : "op");
  const preload = path.join(tmpHome, "fake op preload.cjs");
  try {
    await link(process.execPath, fakeOp);
  } catch {
    await copyFile(process.execPath, fakeOp);
  }
  await chmod(fakeOp, 0o755);
  await writeFile(preload, `
const fs = require("node:fs");
const path = require("node:path");
const fakeExecutable = ${JSON.stringify(fakeOp)};
const actualExecutable = fs.realpathSync.native(process.execPath);
const expectedExecutable = fs.realpathSync.native(fakeExecutable);
const sameExecutable = process.platform === "win32"
  ? actualExecutable.toLowerCase() === expectedExecutable.toLowerCase()
  : actualExecutable === expectedExecutable;
if (sameExecutable) {
  const args = [path.basename(process.argv[1] || ""), ...process.argv.slice(2)];
  let output;
  if (args[0] === "item" && args[1] === "list") {
    output = [
      { id: "aws-dev", title: "AWS-dev", category: "API_CREDENTIAL" },
      { id: "github", title: "GitHub", category: "LOGIN" }
    ];
  } else if (args[0] === "item" && args[1] === "get" && args[2] === "aws-dev") {
    output = {
      id: "aws-dev",
      title: "AWS-dev",
      category: "API_CREDENTIAL",
      fields: [
        { id: "username", label: "username", type: "STRING", purpose: "USERNAME", reference: ${JSON.stringify(opRef("aws-dev", "username"))} },
        { id: "credential", label: "credential", type: "CONCEALED", reference: ${JSON.stringify(opRef("aws-dev", "credential"))} }
      ]
    };
  } else if (args[0] === "item" && args[1] === "get" && args[2] === "github") {
    output = {
      id: "github",
      title: "GitHub",
      category: "LOGIN",
      fields: [
        { id: "notesPlain", label: "notesPlain", type: "STRING", value: "plain text note" },
        { id: "password", label: "password", type: "CONCEALED", purpose: "PASSWORD", reference: ${JSON.stringify(opRef("github", "password"))} }
      ]
    };
  } else if (args[0] === "item" && args[1] === "create") {
    const direct = args.find((arg) => arg.startsWith("--template="));
    const index = args.indexOf("--template");
    const templatePath = direct ? direct.slice("--template=".length) : args[index + 1];
    const template = JSON.parse(fs.readFileSync(templatePath, "utf8"));
    output = {
      id: "created-item",
      title: template.title,
      category: template.category,
      fields: (template.fields || []).map((field) => ({
        ...field,
        reference: "op://${fakeVault}/created-item/" + field.id
      }))
    };
  } else {
    process.stderr.write("unexpected op call: " + args.join(" ") + "\\n");
    process.exit(2);
  }
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}
`);
  const preloadOption = `--require="${preload.replaceAll('"', '\\"')}"`;
  process.env.NODE_OPTIONS = [originalNodeOptions, preloadOption].filter(Boolean).join(" ");
  return fakeOp;
}
