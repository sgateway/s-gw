import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
const file = process.env.SGW_TEST_LOGIN_FILE;
if (process.env.SGW_EXPECT_KEYCHAIN_READ === '1') assert.equal(readFileSync(file, 'utf8'), 'synthetic database');
else assert.throws(() => readFileSync(file));
assert.throws(() => readFileSync(process.env.SGW_TEST_SIBLING_FILE));
assert.throws(() => writeFileSync(file, 'changed'));
assert.throws(() => writeFileSync(process.env.SGW_TEST_CREATED_FILE, 'changed'));
