import { describe, expect, it } from "vitest";
import { scanText } from "../src/scanner.js";
import type { ScanCandidate } from "../src/types.js";

function secretLike(...parts: string[]): string {
  return parts.join("");
}

describe("secret detector rule pack", () => {
  it("detects provider-specific credentials and tokenizes only the sensitive value", async () => {
    const github = secretLike("gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789ABCD");
    const aws = secretLike("A", "KIA", "1234567890ABCDEF");
    const slack = secretLike("xo", "xb-", "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx");
    const dbCreds = "report_user:correct-horse-battery-staple-42";
    const text = [
      `GITHUB_TOKEN=${github}`,
      `AWS_ACCESS_KEY_ID=${aws}`,
      `SLACK_BOT_TOKEN=${slack}`,
      `DATABASE_URL=postgres://${dbCreds}@db.internal:5432/app`
    ].join("\n");

    const seen: ScanCandidate[] = [];
    const result = await scanText(text, (candidate) => {
      seen.push(candidate);
      return `s-gw:test:${candidate.ruleId}`;
    });

    expect(result.findings.map((item) => item.ruleId)).toEqual([
      "SEC-GITHUB-TOKEN",
      "SEC-AWS-ACCESS-KEY",
      "SEC-SLACK-TOKEN",
      "SEC-CONNECTION-STRING"
    ]);
    expect(result.findings.map((item) => item.provider)).toEqual(["github", "aws", "slack", "database"]);
    expect(result.findings.every((item) => item.severity === "critical")).toBe(true);
    expect(seen.every((candidate) => typeof candidate.confidence === "number")).toBe(true);

    for (const value of [github, aws, slack, dbCreds]) {
      expect(result.tokenizedText).not.toContain(value);
    }
    expect(result.tokenizedText).toContain("postgres://<<SGW_SECRET:s-gw:test:SEC-CONNECTION-STRING>>@db.internal");
  });

  it("prefers a specific provider rule over the generic assignment fallback", async () => {
    const key = secretLike("sk", "-proj-", "abcdefghijklmnopqrstuvwxyz1234567890_ABCD");
    const result = await scanText(`OPENAI_API_KEY=${key}`, (candidate) => `s-gw:test:${candidate.ruleId}`);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("SEC-OPENAI-PROJECT");
    expect(result.findings[0].provider).toBe("openai");
    expect(result.findings[0].type).toBe("api-token");
  });

  it("skips obvious documentation placeholders", async () => {
    const placeholder = secretLike("A", "KIA", "IOSFODNN7EXAMPLE");
    const result = await scanText(`aws_key = '${placeholder}'`, (candidate) => {
      return `s-gw:test:${candidate.ruleId}`;
    });

    expect(result.findings).toHaveLength(0);
    expect(result.tokenizedText).toContain(placeholder);
  });

  it("validates JWT structure before tokenizing", async () => {
    const jwt = [
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJhcnJ5In0",
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ].join(".");
    const fake = "eyJnotvalidpayloadnotjson.eyJalsonotjsonpayload.badbadbadbadbadbadbad";

    const result = await scanText(`${jwt}\n${fake}`, (candidate) => `s-gw:test:${candidate.ruleId}`);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("SEC-JWT");
    expect(result.tokenizedText).not.toContain(jwt);
    expect(result.tokenizedText).toContain(fake);
  });
});
