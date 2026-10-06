const SENSITIVE_FIELDS = /^(?:(?:access|refresh|id)?token|apikey|password|passwd|pwd|secret|clientsecret|privatekey|authorization|cookie|setcookie|session|sessionid|credentials)$/;
export const WITHHELD_HTTP_CREDENTIAL = "<SGW_RESPONSE_CREDENTIAL_WITHHELD>";

export function redactHttpCredentialFields(body: string): { body: string; changed: boolean } {
  let parsed: unknown;
  try { parsed = JSON.parse(body); } catch { return { body, changed: false }; }
  if (!parsed || typeof parsed !== "object") return { body, changed: false };
  let changed = false;
  const pending: object[] = [parsed];
  while (pending.length) {
    const object = pending.pop()!;
    for (const [key, value] of Object.entries(object)) {
      if (value !== null && value !== "" && SENSITIVE_FIELDS.test(key.toLowerCase().replace(/[-_]/g, ""))) {
        (object as Record<string, unknown>)[key] = WITHHELD_HTTP_CREDENTIAL;
        changed = true;
      } else if (value && typeof value === "object") pending.push(value);
    }
  }
  return { body: changed ? JSON.stringify(parsed) : body, changed };
}
