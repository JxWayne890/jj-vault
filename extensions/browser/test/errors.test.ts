import assert from 'node:assert/strict';
import test from 'node:test';
import { cleanError } from '../src/errors.ts';

test('a forbidden native host explains that this extension ID must be paired', () => {
  const message = cleanError(new Error('Access to the specified native messaging host is forbidden.'));
  assert.match(message, /extension ID is not authorized/);
  assert.match(message, /Compare the ID under Connect this browser/);
  assert.match(message, /pair this extension again/);
  assert.doesNotMatch(message, /setup steps below/);
});

test('authorization takes precedence over missing registration language', () => {
  assert.match(cleanError(new Error('Native messaging host is FORBIDDEN and not registered for this extension.')), /extension ID is not authorized/);
  assert.match(cleanError(new Error('Not authorised to use this native messaging host.')), /extension ID is not authorized/);
});

test('missing native host registration gives the installation and pairing steps', () => {
  for (const message of [
    'Specified native messaging host not found.',
    'Native messaging host not found.',
    'The native host is not registered.',
  ]) {
    assert.equal(cleanError(new Error(message)), 'Pair this extension with the Mac app using the setup steps below.');
  }
});

test('a stopped app or disconnected native host asks to start and unlock JJ Vault', () => {
  for (const message of [
    'connect ECONNREFUSED: connection refused',
    'Native host has exited.',
    'Native host disconnected.',
    'Could not connect to the service.',
  ]) {
    assert.equal(cleanError(new Error(message)), 'Open JJ Vault on your Mac, unlock it, and try again.');
  }
});

test('a locked vault keeps its specific unlock guidance', () => {
  assert.equal(cleanError(new Error('Vault is locked.')), 'Vault is locked. Unlock JJ Vault on your Mac, then refresh.');
});

test('page restrictions and changed page guidance remain intact', () => {
  for (const message of [
    'Open an HTTPS website to use autofill.',
    'Open a website first.',
    'The page changed. Reopen JJ Vault to continue.',
  ]) {
    assert.equal(cleanError(new Error(message)), message);
  }
});

test('unknown errors are bounded and unknown values get a safe fallback', () => {
  assert.equal(cleanError(new Error('a'.repeat(500))), 'a'.repeat(240));
  for (const error of [undefined, null, 'untrusted error', { message: 'untrusted error' }]) {
    assert.equal(cleanError(error), 'JJ Vault could not complete the request.');
  }
});
