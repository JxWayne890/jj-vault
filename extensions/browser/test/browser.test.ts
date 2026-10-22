import test from 'node:test';
import assert from 'node:assert/strict';
import { matchesUrl, safePageUrl, sameDocument, acceptCapture } from '../src/matching.ts';
import { fieldValue, type FieldDescriptor } from '../src/fields.ts';
import type { BrowserItem } from '../src/types.ts';

const field = (values: Partial<FieldDescriptor>): FieldDescriptor => ({ autocomplete: '', type: 'text', name: '', id: '', label: '', ...values });
const login: BrowserItem = { id: 'fixture', type: 'login', title: 'Example', username: 'fixture@example.test', password: 'fixture password', totp: '123456' };

test('exact host matching rejects phishing, sibling hosts, credentials, downgrade, and alternate ports', () => {
  assert.equal(matchesUrl('https://example.test/login', 'https://example.test/account'), true);
  for (const url of ['https://example.test.evil.test', 'https://login.example.test', 'https://example.test:8443', 'http://example.test', 'https://example.test@evil.test', 'javascript:alert(1)']) assert.equal(matchesUrl('https://example.test', url), false, url);
  assert.equal(safePageUrl('http://example.test'), false);
  assert.equal(safePageUrl('https://user:pass@example.test'), false);
  assert.equal(safePageUrl('file:///tmp/login.html'), false);
});

test('in flight responses are invalidated by navigation including same host paths and query strings', () => {
  assert.equal(sameDocument('https://example.test/login', 'https://example.test/login#form'), true);
  assert.equal(sameDocument('https://example.test/login', 'https://example.test/account'), false);
  assert.equal(sameDocument('https://example.test/login', 'https://example.test/login?redirect=evil'), false);
  assert.equal(sameDocument('https://example.test/login', 'https://evil.test/login'), false);
});

test('save capture accepts only an authenticated extension top frame at the current URL', () => {
  const now = 100_000;
  const candidate = { url: 'https://example.test/login', title: 'Example', username: 'fixture', password: 'synthetic', capturedAt: now };
  const sender = { id: 'extension', frameId: 0, tab: { id: 1, url: candidate.url } };
  assert.equal(acceptCapture(sender, 'extension', candidate, now), true);
  assert.equal(acceptCapture({ ...sender, frameId: 1 }, 'extension', candidate, now), false);
  assert.equal(acceptCapture({ ...sender, id: 'other' }, 'extension', candidate, now), false);
  assert.equal(acceptCapture({ ...sender, tab: { id: 1, url: 'https://example.test/changed' } }, 'extension', candidate, now), false);
  assert.equal(acceptCapture({ ...sender, tab: undefined }, 'extension', candidate, now), false);
  assert.equal(acceptCapture(sender, 'extension', { ...candidate, capturedAt: 1 }, now), false);
  assert.equal(acceptCapture(sender, 'extension', { ...candidate, password: '' }, now), false);
});

test('login mapping fills username, current password, and current TOTP, never new password or arbitrary fields', () => {
  assert.equal(fieldValue(login, field({ autocomplete: 'section-login username' })), login.username);
  assert.equal(fieldValue(login, field({ type: 'password', autocomplete: 'current-password' })), login.password);
  assert.equal(fieldValue(login, field({ autocomplete: 'one-time-code' })), '123456');
  assert.equal(fieldValue(login, field({ type: 'password', autocomplete: 'new-password' })), undefined);
  assert.equal(fieldValue(login, field({ type: 'password', autocomplete: 'off' })), undefined);
  assert.equal(fieldValue(login, field({ name: 'newsletter' })), undefined);
  assert.equal(fieldValue(login, field({ name: 'first_name' })), undefined);
});

test('card mapping is separate from identities and derives expiry fields', () => {
  const card: BrowserItem = { id: 'card', type: 'creditCard', title: 'Fixture card', fields: [{ label: 'Card number', value: '4242424242424242' }, { label: 'Expiration', value: '02/2030' }, { label: 'CVV', value: '000' }] };
  assert.equal(fieldValue(card, field({ autocomplete: 'cc-number' })), '4242424242424242');
  assert.equal(fieldValue(card, field({ autocomplete: 'billing cc-exp-month' })), '02');
  assert.equal(fieldValue(card, field({ autocomplete: 'cc-exp-year' })), '2030');
  assert.equal(fieldValue(card, field({ name: 'cvc' })), '000');
  assert.equal(fieldValue(card, field({ autocomplete: 'username' })), undefined);
  assert.equal(fieldValue(card, field({ type: 'password', name: 'cardnumber' })), undefined);
});

test('identity fields support standard autocomplete and common labels without filling password fields', () => {
  const identity: BrowserItem = { id: 'identity', type: 'identity', title: 'Fixture identity', fields: [{ label: 'First name', value: 'Example' }, { label: 'Last name', value: 'Person' }, { label: 'Street address', value: '123 Sample Lane' }, { label: 'City', value: 'Austin' }, { label: 'Postal code', value: '00000' }] };
  assert.equal(fieldValue(identity, field({ autocomplete: 'given-name' })), 'Example');
  assert.equal(fieldValue(identity, field({ name: 'last_name' })), 'Person');
  assert.equal(fieldValue(identity, field({ autocomplete: 'shipping address-line1' })), '123 Sample Lane');
  assert.equal(fieldValue(identity, field({ autocomplete: 'address-level2' })), 'Austin');
  assert.equal(fieldValue(identity, field({ name: 'zip' })), '00000');
  assert.equal(fieldValue(identity, field({ type: 'password', name: 'zip' })), undefined);
  assert.equal(fieldValue(identity, field({ autocomplete: 'cc-number' })), undefined);
});
