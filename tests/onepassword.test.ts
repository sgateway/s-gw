import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanTextToOnePassword } from "../src/gateway.js";
import { listOnePasswordSecretReferences, onePasswordStatus } from "../src/onepassword.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const fakeVault = "Example";

function opRef(item: string, field: string): string {
  return `op://${fakeVault}/${item}/${field}`;
}

function fakeOpenAiToken(): string {
  return ["sk", "-proj-", "captured_dummy_1234567890abcdef"].join("");
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-op-test-"));
});

afterEach(async () => {
  delete process.env.SGW_OP_CLI;
  delete process.env.SGW_REAL_OP_PATH;
  delete process.env.SGW_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
  }
});

describe("1Password metadata importer", () => {
  it("uses the real gated op binary for brokered s-gw reads when available", async () => {
    const fakeRealOp = await writeFakeOp();
    process.env.SGW_REAL_OP_PATH = fakeRealOp;

    const status = onePasswordStatus();

    expect(status.available).toBe(true);
    expect(status.command).toBe(fakeRealOp);
    expect(status.version).toBe("2.32.0");
  });

  it("discovers secret-like fields without returning field values", async () => {
    process.env.SGW_OP_CLI = await writeFakeOp();

    const status = onePasswordStatus();
    expect(status.available).toBe(true);
    expect(status.version).toBe("2.32.0");

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
  const fakeOp = path.join(tmpHome, "op");
  await writeFile(fakeOp, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '2.32.0\\n'
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "list" ]; then
  cat <<'JSON'
[
  {"id":"aws-dev","title":"AWS-dev","category":"API_CREDENTIAL"},
  {"id":"github","title":"GitHub","category":"LOGIN"}
]
JSON
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "get" ] && [ "$3" = "aws-dev" ]; then
  cat <<'JSON'
{
  "id":"aws-dev",
  "title":"AWS-dev",
  "category":"API_CREDENTIAL",
  "fields":[
    {"id":"username","label":"username","type":"STRING","purpose":"USERNAME","reference":"${opRef("aws-dev", "username")}"},
    {"id":"credential","label":"credential","type":"CONCEALED","reference":"${opRef("aws-dev", "credential")}"}
  ]
}
JSON
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "get" ] && [ "$3" = "github" ]; then
  cat <<'JSON'
{
  "id":"github",
  "title":"GitHub",
  "category":"LOGIN",
  "fields":[
    {"id":"notesPlain","label":"notesPlain","type":"STRING","value":"plain text note"},
    {"id":"password","label":"password","type":"CONCEALED","purpose":"PASSWORD","reference":"${opRef("github", "password")}"}
  ]
}
JSON
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "create" ]; then
  template=""
  previous=""
  for arg in "$@"; do
    if [ "$previous" = "--template" ]; then
      template="$arg"
    fi
    case "$arg" in
      --template=*) template="\${arg#--template=}" ;;
    esac
    previous="$arg"
  done
  node - "$template" <<'NODE'
const fs = require("node:fs");
const template = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const fields = (template.fields || []).map((field) => ({
  ...field,
  reference: "op://${fakeVault}/created-item/" + field.id
}));
process.stdout.write(JSON.stringify({
  id: "created-item",
  title: template.title,
  category: template.category,
  fields
}));
NODE
  exit 0
fi
printf 'unexpected op call: %s %s %s\\n' "$1" "$2" "$3" >&2
exit 2
`);
  await chmod(fakeOp, 0o755);
  return fakeOp;
}
