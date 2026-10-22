#!/usr/bin/env node
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { isDirectExecution } from './entrypoint.ts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

export type AgentClient = string;
export const AGENT_TOOLS = ['add_login', 'delete_login', 'generate_password', 'get_login', 'list_logins', 'search_items', 'update_login'];
export interface AgentClientOptions { directory?: string; port?: number; output?: (value: string) => void; input?: AsyncIterable<string|Buffer> }
const invalidClientNames = new Set(['admin','owner','cli','browser','provider','admin-token','browser-token','provider-token']);
export function validateAgentClient(value: string | undefined): AgentClient {
  if (!value || !/^[a-z][a-z0-9_-]{0,63}$/.test(value) || invalidClientNames.has(value)) throw new Error('Invalid agent client name. Use a lowercase name beginning with a letter, then letters, numbers, underscores, or hyphens.');
  return value;
}
function endpoint(options: AgentClientOptions): URL {
  const candidate = options.port ?? Number(process.env.JJ_VAULT_PORT ?? 17373);
  if (!Number.isSafeInteger(candidate) || candidate < 1 || candidate > 65535) throw new Error('Invalid local port');
  return new URL(`http://127.0.0.1:${candidate}/mcp`);
}
/** Read only a named assistant token. Owner, browser, and provider token names are reserved. */
export async function readAgentToken(client: string, options: AgentClientOptions = {}): Promise<string> {
  const name = validateAgentClient(client);
  const directory = resolve(options.directory ?? process.env.JJ_VAULT_AGENT_DIR ?? join(homedir(), 'Library', 'Application Support', 'JJ Vault', 'agent-tokens'));
  let handle;
  try {
    const dir = await lstat(directory);
    if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o7777) !== 0o700 || (process.getuid && dir.uid !== process.getuid())) throw new Error('permissions');
    handle = await open(join(directory, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o7777) !== 0o600 || (process.getuid && stat.uid !== process.getuid()) || stat.size > 1024) throw new Error('permissions');
    const bytes = Buffer.alloc(1025); let length = 0;
    while (length < bytes.length) { const read = await handle.read(bytes, length, bytes.length - length, null); if (!read.bytesRead) break; length += read.bytesRead; }
    const token = bytes.subarray(0, length).toString('ascii').trim(); const ascii = bytes.subarray(0, length).every(byte => byte < 128); bytes.fill(0);
    if (length > 1024 || !ascii || !/^[A-Za-z0-9_-]{43,1024}$/.test(token)) throw new Error('invalid token');
    return token;
  } catch { throw new Error('Agent token unavailable. It must be a regular file owned by this user with mode 0600 inside an owner directory with mode 0700.'); }
  finally { await handle?.close(); }
}
const safeMessages = ['Vault is locked','Agent token is invalid or revoked','Agent permission denied','Login not found or not allowed','Invalid agent request','JJ Vault request failed','Rate limit reached: thirty writes per hour per agent','Rate limit reached: ten login requests per hour per agent'];
function resultText(result: unknown): string {
  if (!result || typeof result !== 'object' || !('content' in result)) throw new Error('Invalid JJ Vault response');
  const content = result.content;
  if (!Array.isArray(content) || content.length !== 1 || content[0]?.type !== 'text' || typeof content[0].text !== 'string' || content[0].text.length > 1024 * 1024) throw new Error('Invalid JJ Vault response');
  if ('isError' in result && result.isError) throw new Error(safeMessages.includes(content[0].text) ? content[0].text : 'JJ Vault request failed');
  return content[0].text;
}
async function connectAgent<T>(clientName: AgentClient, options: AgentClientOptions, action: (client: Client) => Promise<T>): Promise<T> {
  const url = endpoint(options); const token = await readAgentToken(clientName, options);
  const client = new Client({ name: `JJ Vault ${clientName} helper`, version: '1.1.0' }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: { headers: { Authorization: `Bearer ${token}` }, redirect: 'error' },
    fetch: async (input, init) => {
      if (String(input) !== url.href) throw new Error('Invalid local endpoint');
      let response: Response;
      try { response = await fetch(input, { ...init, redirect: 'error', signal: AbortSignal.any([...(init?.signal ? [init.signal] : []), AbortSignal.timeout(10000)]) }); }
      catch { throw new Error('JJ Vault is unavailable. Open the Mac app.'); }
      if (response.status === 423) { await response.body?.cancel(); throw new Error('Vault is locked'); }
      if (response.status === 401 || response.status === 403) { await response.body?.cancel(); throw new Error('JJ Vault agent token is invalid or revoked'); }
      if (!response.ok && response.status !== 405) { await response.body?.cancel(); throw new Error('JJ Vault request failed'); }
      return response;
    },
    reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1000, maxReconnectionDelay: 1000, reconnectionDelayGrowFactor: 1 }
  });
  try { await client.connect(transport); return await action(client); }
  catch (error) {
    const message = error instanceof Error ? error.message : '';
    if ([...safeMessages,'JJ Vault is unavailable. Open the Mac app.','JJ Vault agent token is invalid or revoked','Invalid JJ Vault response','Unexpected JJ Vault tools'].includes(message)) throw new Error(message);
    throw new Error('JJ Vault request failed');
  } finally { await client.close().catch(() => {}); }
}
async function readInput(options: AgentClientOptions): Promise<Record<string, unknown>> {
  const input = options.input ?? process.stdin; let length = 0; const chunks: Buffer[] = [];
  if (input === process.stdin && process.stdin.isTTY) throw new Error('Supply one JSON object through stdin or a pipe. Never put secrets in command arguments.');
  try {
    for await (const chunk of input) { const bytes = Buffer.from(chunk); length += bytes.length; if (length > 128 * 1024) throw new Error(); chunks.push(bytes); }
    const bytes = Buffer.concat(chunks); let value: unknown;
    try { value = JSON.parse(bytes.toString('utf8')); } finally { bytes.fill(0); }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch { throw new Error('Invalid stdin JSON. Supply one object of at most 128 KiB.'); }
  finally { for (const chunk of chunks) chunk.fill(0); }
}
const fieldKeys = new Set(['name','website','username','password','notes','totp_secret','tags']);
function validateFields(input: Record<string, unknown>, add = false): void {
  const keys = new Set([...fieldKeys, ...(add ? ['vault'] : [])]);
  if (!Object.keys(input).length || Object.keys(input).some(key => !keys.has(key))) throw new Error('Invalid stdin fields');
  for (const [key, value] of Object.entries(input)) {
    if (key === 'tags') { if (!Array.isArray(value) || value.length > 100 || value.some(tag => typeof tag !== 'string' || tag.length > 100)) throw new Error('Invalid stdin fields'); }
    else if (typeof value !== 'string' || value.length > (key === 'notes' ? 100000 : key === 'website' || key === 'totp_secret' ? 4096 : key === 'name' || key === 'vault' ? 500 : 4096)) throw new Error('Invalid stdin fields');
  }
  if (add && ['vault','name','website','username'].some(key => typeof input[key] !== 'string') || ('name' in input && !String(input.name).trim()) || (add && !String(input.vault).trim())) throw new Error('Invalid stdin fields');
}
function metadata(value: unknown): {name:string;website:string;vault:string;tags:string[]} {
  if (!value || typeof value !== 'object') throw new Error('Invalid JJ Vault response'); const v = value as Record<string, unknown>;
  if (typeof v.name !== 'string' || typeof v.website !== 'string' || typeof v.vault !== 'string' || !Array.isArray(v.tags) || !v.tags.every(t => typeof t === 'string')) throw new Error('Invalid JJ Vault response');
  return { name: v.name, website: v.website, vault: v.vault, tags: v.tags as string[] };
}
const usage = 'Usage: jjvault-agent check|list|headers CLIENT; get|delete CLIENT NAME; search CLIENT QUERY; add|update|generate CLIENT < input.json. Never put secrets in arguments.';
export async function runAgentClient(args: string[], options: AgentClientOptions = {}): Promise<void> {
  const [command, requestedClient, name] = args; const output = options.output ?? (value => process.stdout.write(value + '\n'));
  if (['help','--help','-h'].includes(command ?? '') && args.length === 1) { output(usage + '\nCLIENT is your own registered agent client name. Unlock only in the Mac app.\nupdate stdin: {"name":"Exact existing name","fields":{"password":"new value"}}\ngenerate stdin: {"length":32,"options":{"symbols":true}}'); return; }
  const simple = ['headers','check','list'].includes(command ?? ''); const named = ['get','delete','search'].includes(command ?? ''); const stdin = ['add','update','generate'].includes(command ?? '');
  if ((!simple && !named && !stdin) || args.length !== (named ? 3 : 2)) throw new Error(usage);
  const clientName = validateAgentClient(requestedClient); endpoint(options);
  if (command === 'headers') { output(JSON.stringify({ Authorization: `Bearer ${await readAgentToken(clientName, options)}` })); return; }
  if (named && (typeof name !== 'string' || (command !== 'search' && !name.trim()) || name.length > (command === 'search' ? 512 : 500))) throw new Error('An exact login name or bounded search query is required');
  let payload: Record<string, unknown> = {};
  if (stdin) {
    payload = await readInput(options);
    if (command === 'add') validateFields(payload, true);
    if (command === 'update') { if (Object.keys(payload).sort().join(',') !== 'fields,name' || typeof payload.name !== 'string' || !payload.name.trim() || payload.name.length > 500 || !payload.fields || typeof payload.fields !== 'object' || Array.isArray(payload.fields)) throw new Error('Invalid stdin fields'); validateFields(payload.fields as Record<string, unknown>); }
    if (command === 'generate') {
      if (Object.keys(payload).some(key => !['length','options'].includes(key)) || ('length' in payload && (!Number.isInteger(payload.length) || Number(payload.length) < 4 || Number(payload.length) > 256))) throw new Error('Invalid stdin fields');
      if ('options' in payload) { const o = payload.options; if (!o || typeof o !== 'object' || Array.isArray(o) || Object.keys(o).some(key => !['mode','upper','lower','digits','symbols','separator','words'].includes(key))) throw new Error('Invalid stdin fields'); }
    }
  }
  await connectAgent(clientName, options, async client => {
    if (command === 'check') { const tools = (await client.listTools()).tools.map(tool => tool.name).sort(); if (JSON.stringify(tools) !== JSON.stringify(AGENT_TOOLS)) throw new Error('Unexpected JJ Vault tools'); output(JSON.stringify({ connected: true, client: clientName, endpoint: endpoint(options).href, tools })); return; }
    const toolName = ({ list:'list_logins', get:'get_login', add:'add_login', update:'update_login', delete:'delete_login', generate:'generate_password', search:'search_items' } as Record<string, string>)[command];
    const arguments_ = command === 'get' || command === 'delete' ? { name } : command === 'search' ? { query: name } : payload;
    const value = JSON.parse(resultText(await client.callTool({ name: toolName, arguments: arguments_ })));
    if (command === 'list') { if (!Array.isArray(value)) throw new Error('Invalid JJ Vault response'); output(JSON.stringify(value.map(metadata))); }
    else if (command === 'search') { if (!Array.isArray(value) || !value.every(v => v && typeof v.name === 'string' && typeof v.website === 'string')) throw new Error('Invalid JJ Vault response'); output(JSON.stringify(value.map(v => ({ name: v.name, website: v.website })))); }
    else if (command === 'add' || command === 'update') output(JSON.stringify(metadata(value)));
    else if (command === 'delete') { if (!value || typeof value.name !== 'string' || value.deleted !== true || typeof value.restoreUntil !== 'string' || !Number.isFinite(Date.parse(value.restoreUntil))) throw new Error('Invalid JJ Vault response'); output(JSON.stringify({ name:value.name, deleted:true, restoreUntil:value.restoreUntil })); }
    else if (command === 'generate') { if (!value || typeof value.password !== 'string') throw new Error('Invalid JJ Vault response'); output(JSON.stringify({ password: value.password })); }
    else { if (!value || typeof value.username !== 'string' || typeof value.password !== 'string' || (value.totp !== undefined && (typeof value.totp !== 'string' || !/^\d{6,8}$/.test(value.totp)))) throw new Error('Invalid JJ Vault response'); output(JSON.stringify({ username:value.username, password:value.password, ...(value.totp ? { totp:value.totp } : {}) })); }
  });
}
if (isDirectExecution(import.meta.url) && /(?:^|[\\/])agent-client\.(?:ts|mjs|cjs)$/.test(process.argv[1])) void runAgentClient(process.argv.slice(2)).catch(error => { process.stderr.write((error instanceof Error ? error.message : 'JJ Vault request failed') + '\n'); process.exitCode = 1; });
