import { SecretStore } from "../../src/store.js";

const store = new SecretStore();
const operation = process.argv[2];

if (operation === "add-secret") {
  await store.addSecret({
    name: "synthetic local item",
    type: "api-token",
    value: "synthetic-local-value-123456789",
    policy: { injectEnv: "SYNTHETIC_TOKEN" }
  });
} else if (operation === "add-keychain") {
  await store.addKeychainSecret({
    name: "synthetic Keychain item",
    type: "api-token",
    value: "synthetic-keychain-value-123456789",
    policy: { injectEnv: "SYNTHETIC_TOKEN" }
  });
} else if (operation === "add-onepassword") {
  await store.addOnePasswordReference({
    name: "synthetic reference",
    type: "api-token",
    reference: "op://Example/synthetic-item/credential",
    policy: { injectEnv: "SYNTHETIC_TOKEN" }
  });
} else if (operation === "add-policy") {
  await store.addApprovalPolicyRule({
    name: "Concurrent synthetic writer",
    decision: "deny",
    conditions: { agents: ["synthetic-agent"] }
  });
} else if (operation === "delete-keychain") {
  const [item] = await store.listHandles();
  if (!item) throw new Error("Synthetic Keychain item is missing.");
  await store.deleteSecret(item.handle);
} else {
  throw new Error(`Unknown Keychain lock test operation: ${operation}`);
}
