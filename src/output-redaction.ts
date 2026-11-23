import { sanitizeKnownSecrets, tokenForHandle } from "./scanner.js";

export const SGW_OUTPUT_TRUNCATED = "\n<<SGW_OUTPUT_TRUNCATED>>";
export const MIN_STABLE_SECRET_FRAGMENT = 6;
export const MAX_CAPTURE_HEADROOM_BYTES = 1_048_576;
export const MIN_ENCODED_SECRET_LENGTH = 8;

type SecretPair = { handle: string; value: string };

export function utf8ByteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

export function captureHeadroomBytes(values: string[]): number {
  const seen = new Set<string>();
  let sum = 0;
  for (const value of values) {
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    sum += utf8ByteLength(value);
  }
  return Math.min(sum, MAX_CAPTURE_HEADROOM_BYTES);
}

export function clipUtf8Bytes(text: string, maxBytes: number): string {
  if (maxBytes <= 0) {
    return "";
  }
  if (utf8ByteLength(text) <= maxBytes) {
    return text;
  }

  const buf = Buffer.from(text, "utf8");
  let end = Math.min(maxBytes, buf.length);
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end -= 1;
  }
  return buf.subarray(0, end).toString("utf8");
}

export function capUtf8Bytes(text: string, maxBytes: number): string {
  if (utf8ByteLength(text) <= maxBytes) {
    return text;
  }
  return `${clipUtf8Bytes(text, maxBytes)}${SGW_OUTPUT_TRUNCATED}`;
}

export function appendUtf8Bounded(
  current: string,
  extra: string,
  maxBytes: number
): { text: string; truncated: boolean } {
  const combined = current + extra;
  if (utf8ByteLength(combined) <= maxBytes) {
    return { text: combined, truncated: false };
  }
  return { text: clipUtf8Bytes(combined, maxBytes), truncated: true };
}

export function encodedSecretForms(value: string): string[] {
  if (value.length < MIN_ENCODED_SECRET_LENGTH) {
    return [];
  }
  const raw = Buffer.from(value, "utf8");
  const hex = raw.toString("hex");
  const candidates = [
    raw.toString("base64"),
    raw.toString("base64url"),
    hex,
    hex.toUpperCase(),
    uriEncoded(value)
  ];
  const forms: string[] = [];
  for (const form of candidates) {
    if (form === value || form.length < MIN_ENCODED_SECRET_LENGTH || forms.includes(form)) {
      continue;
    }
    forms.push(form);
  }
  return forms;
}

export function sanitizeKnownSecretForms(text: string, pairs: SecretPair[]): string {
  let out = text;
  const ordered = [...pairs].sort((left, right) => right.value.length - left.value.length);
  for (const pair of ordered) {
    // sanitizeKnownSecrets goes longest first, so padded base64 is replaced
    // before its unpadded twin and no stray "=" is left behind.
    out = sanitizeKnownSecrets(out, withEncodedForms([pair]));
  }
  return out;
}

export function sanitizeCapturedOutput(
  text: string,
  pairs: SecretPair[],
  maxBytes: number,
  options: { rawTruncated?: boolean; encodedForms?: boolean; fragmentsOnlyWhenTruncated?: boolean } = {}
): { text: string; changed: boolean } {
  const body = stripTrailingTruncationMarkers(text);
  const replaced = options.encodedForms
    ? sanitizeKnownSecretForms(body, pairs)
    : sanitizeKnownSecrets(body, pairs);
  const minFragment = trailingFragmentFloor(options);
  // A capture cut can land inside an encoded copy too, so those prefixes count as fragments.
  const fragmentPairs = options.encodedForms ? withEncodedForms(pairs) : pairs;
  const redacted = redactTrailingSecretFragments(replaced, fragmentPairs, minFragment);
  return {
    text: capUtf8Bytes(redacted, maxBytes),
    changed: redacted !== body
  };
}

function trailingFragmentFloor(options: { rawTruncated?: boolean; fragmentsOnlyWhenTruncated?: boolean }): number {
  if (options.rawTruncated) {
    return 1;
  }
  // Command output is arbitrary text: a complete stream that merely ends in a
  // word shared with a secret's prefix must come back unchanged.
  return options.fragmentsOnlyWhenTruncated ? 0 : MIN_STABLE_SECRET_FRAGMENT;
}

function withEncodedForms(pairs: SecretPair[]): SecretPair[] {
  const out: SecretPair[] = [];
  for (const pair of pairs) {
    if (!pair.value) {
      continue;
    }
    out.push(pair);
    for (const form of encodedSecretForms(pair.value)) {
      out.push({ handle: pair.handle, value: form });
    }
  }
  return out;
}

function uriEncoded(value: string): string {
  try {
    return encodeURIComponent(value);
  } catch {
    // Lone surrogates cannot be percent-encoded; there is no such form to redact.
    return "";
  }
}

export function redactTrailingSecretFragments(
  text: string,
  pairs: Array<{ handle: string; value: string }>,
  minFragment: number
): string {
  const body = stripTrailingTruncationMarkers(text);
  if (!body || minFragment <= 0) {
    return body;
  }

  let bestLen = 0;
  let bestHandle = "";
  for (const pair of pairs) {
    if (!pair.value) {
      continue;
    }
    const max = Math.min(body.length, pair.value.length);
    for (let len = max; len >= minFragment; len--) {
      if (pair.value.startsWith(body.slice(body.length - len))) {
        if (len > bestLen) {
          bestLen = len;
          bestHandle = pair.handle;
        }
        break;
      }
    }
  }

  if (bestLen === 0) {
    return body;
  }
  return `${body.slice(0, body.length - bestLen)}${tokenForHandle(bestHandle)}`;
}

function stripTrailingTruncationMarkers(text: string): string {
  let body = text;
  while (body.endsWith(SGW_OUTPUT_TRUNCATED)) {
    body = body.slice(0, -SGW_OUTPUT_TRUNCATED.length);
  }
  return body;
}
