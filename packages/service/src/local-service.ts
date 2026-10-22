import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { matchesUrl, totp, isAssistantForbidden, type VaultEngine, type Item, type TokenRecord } from '../../core/src/index.ts';
import { bearer, json, randomToken, readJson, requireStrongToken, safeError, tokenEqual } from './security.ts';

export interface AssistantNotification {
  type: 'assistant_request'|'assistant_write';
  action: 'get'|'add'|'edit'|'delete';
  agentClientName: string; agentName: string; name: string; itemName?: string; itemId?: string; at: string;
}
export interface LocalServiceOptions {
  port?: number;
  adminToken: string;
  browserToken?: string;
  providerToken?: string;
  provider?: (body: any) => Promise<unknown>;
  allowedOrigins?: string[];
  allowedHosts?: string[];
  notify?: (event: AssistantNotification) => Promise<void>;
}
function assistantItemFingerprint(engine: VaultEngine, token: string, name: string): string | null {
  const data = engine.data(); const agent = engine.authenticateToken(token);
  if (!agent) return null;
  const matches = data.items.filter(item => item.title === name && item.type === 'login' && !isAssistantForbidden(item) && (!data.settings.agentRequireItemApproval || item.allowAssistant) && !item.archived && !item.deletedAt && data.vaults.some(v => v.id === item.vaultId && agent.vaultIds.includes(v.id) && v.allowAssistant && (!data.settings.travelMode || v.travelSafe)));
  if (matches.length !== 1) return null;
  const item = matches[0];
  return createHash('sha256').update(JSON.stringify([item.id,item.vaultId,item.type,item.title,item.username,item.password,item.totp,item.urls,item.allowAssistant,item.updatedAt])).digest('hex');
}
function policyFingerprint(agent: TokenRecord): string {
  return JSON.stringify([agent.id, agent.name, agent.clientName, agent.permission, [...agent.vaultIds].sort(), agent.revokedAt || null]);
}
function assistantSafeError(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (message === 'Vault is locked') return message;
  if (message === 'Unauthorized' || message === 'Invalid API token' || message === 'Invalid or revoked assistant token') return 'Agent token is invalid or revoked';
  if (/^Rate limit/.test(message)) return message.includes('write') ? 'Rate limit reached: thirty writes per hour per agent' : 'Rate limit reached: ten login requests per hour per agent';
  if (/^(Permission denied|Agent permission|Agent access changed|Insufficient)/.test(message)) return 'Agent permission denied';
  if (/^(Allowed login not found|Login not found|No allowed|Item not found|Ambiguous|Assistant|Travel|Not allowed|Bank|X Money|Forbidden|Vault not allowed|Agent vault access denied|Multiple allowed logins)/.test(message)) return 'Login not found or not allowed';
  if (/^(Invalid|Choose|Select|An? |Unsupported|Unknown|At least)/.test(message)) return 'Invalid agent request';
  return 'JJ Vault request failed';
}
const boundedText = z.string().max(4096);
const loginFields = { name: z.string().min(1).max(500), website: z.string().max(4096), username: boundedText, password: boundedText.optional(), notes: z.string().max(100000).optional(), totp_secret: z.string().max(4096).optional(), tags: z.array(z.string().max(100)).max(100).optional() };
const generationOptions = z.object({ mode: z.enum(['random','passphrase','pin']).optional(), upper: z.boolean().optional(), lower: z.boolean().optional(), digits: z.boolean().optional(), symbols: z.boolean().optional(), separator: z.string().max(10).optional(), words: z.number().int().min(4).max(20).optional() }).strict();
const assistantSchemas = {
  list_logins: z.object({}).strict(),
  get_login: z.object({ name: loginFields.name }).strict(),
  add_login: z.object({ vault: z.string().min(1).max(500), ...loginFields }).strict(),
  update_login: z.object({ name: loginFields.name, fields: z.object(loginFields).partial().strict().refine(value => Object.keys(value).length > 0) }).strict(),
  delete_login: z.object({ name: loginFields.name }).strict(),
  generate_password: z.object({ length: z.number().int().min(4).max(256).optional(), options: generationOptions.optional() }).strict(),
  search_items: z.object({ query: z.string().max(512) }).strict()
};
const assistantActions: Record<keyof typeof assistantSchemas, string> = { list_logins:'assistant.list', get_login:'assistant.get', add_login:'assistant.add', update_login:'assistant.edit', delete_login:'assistant.delete', generate_password:'assistant.generate', search_items:'assistant.search' };
function recognizedTool(value: unknown): value is keyof typeof assistantSchemas { return typeof value === 'string' && Object.hasOwn(assistantSchemas, value); }
function auditItemName(body: any): string | undefined { const name = body?.params?.arguments?.name; return typeof name === 'string' && name.length <= 512 ? name : undefined; }

function visibleItems(engine: VaultEngine): Item[] {
  const data = engine.data();
  return data.items.filter(i => !i.deletedAt && !i.archived && data.vaults.some(v => v.id === i.vaultId && (!data.settings.travelMode || v.travelSafe)));
}
const cardFieldNames = new Set('ccname cardholder cardholdername nameoncard ccnumber cardnumber creditcardnumber number ccexp expiry expirydate expiration expirationdate ccexpmonth expmonth expirationmonth month ccexpyear expyear expirationyear year cccsc cvv cvc securitycode'.split(' '));
const identityFieldNames = new Set('name fullname givenname firstname familyname lastname surname additionalname middlename email emailaddress tel phone telephone mobile phonenumber organization company companyname streetaddress address street addressline1 address1 addressline2 address2 apartment suite addresslevel2 city town addresslevel1 state province region postalcode zip zipcode postcode country countrycode'.split(' '));
async function autofillItem(item: Item) {
  const base = { id: item.id, title: item.title, type: item.type, urls: item.urls };
  if (item.type === 'login') return { ...base, username: item.username, password: item.password, fields: [], ...(item.totp ? { totp: await totp(item.totp) } : {}) };
  const allowed = item.type === 'creditCard' ? cardFieldNames : identityFieldNames;
  return { ...base, fields: item.fields.filter(field => allowed.has(field.label.toLowerCase().replace(/[^a-z0-9]/g, ''))) };
}
async function browserAction(engine: VaultEngine, body: any): Promise<unknown> {
  if (typeof body.url !== 'string' || body.url.length > 4096) throw new Error('Invalid page URL');
  const page = new URL(body.url);
  if (!['https:', 'http:'].includes(page.protocol) || page.username || page.password) throw new Error('Invalid page URL');
  if (body.action === 'list') return engine.browserList(body.url);
  if (body.action === 'get') {
    if (typeof body.id !== 'string') throw new Error('Invalid item ID');
    const item = await engine.browserGet(body.id, body.url);
    if (!['login', 'creditCard', 'identity'].includes(item.type)) throw new Error('Browser access denied');
    const result = await autofillItem(item);
    if (engine.status().locked || !engine.browserList(body.url).some(entry => entry.id === item.id)) throw new Error('Vault is locked');
    return result;
  }
  if (body.action === 'save') {
    const input = body.item;
    if (!input || input.type !== 'login' || typeof input.title !== 'string' || input.title.length > 500 || typeof input.password !== 'string' || input.password.length > 10000 || (input.username !== undefined && typeof input.username !== 'string')) throw new Error('Invalid login');
    const data = engine.data();
    const old = input.id ? data.items.find(i => i.id === input.id) : undefined;
    if (input.id && (!old || !engine.browserList(body.url).some(i => i.id === old.id) || old.type !== 'login')) throw new Error('Browser update denied');
    const vault = data.vaults.find(v => v.id === (old?.vaultId || input.vaultId) && v.allowBrowser && (!data.settings.travelMode || v.travelSafe)) || (!input.vaultId && !old ? data.vaults.find(v => v.allowBrowser && (!data.settings.travelMode || v.travelSafe)) : undefined);
    if (!vault) throw new Error('No allowed browser vault');
    const urls = input.urls || [page.origin];
    if (!Array.isArray(urls) || !urls.length || urls.length > 10 || !urls.every((url: unknown) => typeof url === 'string' && matchesUrl(url, body.url))) throw new Error('Browser URL mismatch');
    const item = await engine.upsertItem({ ...(old || {}), title: input.title, type: 'login', vaultId: vault.id, username: input.username || '', password: input.password, urls, ...(old ? {} : { allowAssistant: false }) });
    await engine.record('browser.save', item.id);
    return { id: item.id, title: item.title };
  }
  throw new Error('Unsupported browser action');
}
async function adminAction(engine: VaultEngine, body: any): Promise<unknown> {
  if (body.action === 'status') return engine.status();
  if (body.action === 'lock') { engine.lock(); return engine.status(); }
  if (engine.status().locked) throw new Error('Vault is locked');
  if (body.action === 'search') {
    const query = typeof body.query === 'string' ? body.query.toLowerCase().slice(0, 1000) : '';
    return visibleItems(engine).filter(i => [i.title, i.username || '', ...i.urls, ...i.tags].join('\n').toLowerCase().includes(query)).map(i => ({ id: i.id, title: i.title, type: i.type, username: i.username, urls: i.urls }));
  }
  if (body.action === 'get') {
    const found = visibleItems(engine).filter(i => i.id === body.id || (body.name && i.title === body.name));
    if (found.length !== 1) throw new Error(found.length ? 'Ambiguous item name, use ID' : 'Item not found');
    await engine.record('cli.read', found[0].id);
    const result = { ...found[0], passkey: found[0].passkey ? { ...found[0].passkey, privateKey: undefined } : undefined, currentTotp: found[0].totp ? await totp(found[0].totp) : undefined };
    if (engine.status().locked || !visibleItems(engine).some(entry => entry.id === found[0].id)) throw new Error('Vault is locked');
    return result;
  }
  throw new Error('Unsupported admin action');
}
export async function startLocalService(engine: VaultEngine, options: LocalServiceOptions): Promise<{ port: number; browserToken: string; close(): Promise<void> }> {
  requireStrongToken(options.adminToken, 'Admin token');
  const browserToken = options.browserToken || randomToken(); requireStrongToken(browserToken, 'Browser token');
  if (tokenEqual(browserToken, options.adminToken)) throw new Error('Browser and admin tokens must differ');
  if (options.providerToken) { requireStrongToken(options.providerToken, 'Provider token'); if (tokenEqual(options.providerToken, options.adminToken) || tokenEqual(options.providerToken, browserToken)) throw new Error('Provider token must differ from other tokens'); }
  const transports = new Set<StreamableHTTPServerTransport>();
  let actualPort = options.port ?? 17373;
  const server = createServer((req, res) => { void handle(req, res).catch(error => { if (!res.headersSent) json(res, error instanceof Error && error.message === 'Vault is locked' ? 423 : 400, { ok: false, error: safeError(error) }); else res.end(); }); });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.maxHeadersCount = 40;
  async function handle(req: IncomingMessage, res: ServerResponse) {
    res.setHeader('Cache-Control', 'no-store');
    const allowedHosts = new Set([`127.0.0.1:${actualPort}`, `localhost:${actualPort}`, ...(options.allowedHosts || [])]);
    if (!req.headers.host || !allowedHosts.has(req.headers.host)) { json(res, 403, { error: 'Forbidden host' }); return; }
    const origin = req.headers.origin;
    if (origin && !(options.allowedOrigins || []).includes(origin)) { json(res, 403, { error: 'Forbidden origin' }); return; }
    const path = new URL(req.url || '/', `http://127.0.0.1:${actualPort}`).pathname;
    if (!['/mcp', '/browser', '/admin', '/provider'].includes(path)) { json(res, 404, { error: 'Not found' }); return; }
    const token = bearer(req);
    if (path === '/mcp') {
      async function auditDeniedRequest() {
        if (req.method !== 'POST' || !token) return;
        try {
          const input = await readJson(req);
          if (input?.method !== 'tools/call') return;
          const toolName = input.params?.name; if (!recognizedTool(toolName)) return;
          await engine.auditAssistantAttempt(token!, assistantActions[toolName], auditItemName(input), 'denied');
        } catch { /* Audit failure never exposes request text or changes the rejection. */ }
      }
      if (engine.status().locked) { await auditDeniedRequest(); json(res, 423, { error: 'Vault is locked' }); return; }
      if (!token || tokenEqual(token, options.adminToken) || tokenEqual(token, browserToken) || (options.providerToken && tokenEqual(token, options.providerToken)) || !engine.authenticateToken(token)) { await auditDeniedRequest(); json(res, 401, { error: 'Unauthorized' }); return; }
      const mcp = new McpServer({ name: 'JJ Vault', version: '1.1.0' });
      const sessionVersion = engine.sessionVersion(); const authenticated = engine.authenticateToken(token)!;
      const fingerprint = policyFingerprint(authenticated);
      function assertSession() {
        if (engine.status().locked || engine.sessionVersion() !== sessionVersion) throw new Error('Vault is locked');
        const live = engine.authenticateToken(token);
        if (!live || policyFingerprint(live) !== fingerprint) throw new Error('Agent permission denied');
      }
      async function notification(action: AssistantNotification['action'], name: string) {
        if (!options.notify || (action === 'get' && !engine.data().settings.notifyAssistant)) return;
        const event: AssistantNotification = { type: action === 'get' ? 'assistant_request' : 'assistant_write', action, agentClientName: authenticated.clientName, agentName: authenticated.name, name, itemName: name, at: new Date().toISOString() };
        try { await options.notify(event); }
        catch { if (!engine.status().locked) await engine.record('assistant.notification_failed', undefined, JSON.stringify({ agentClientName: event.agentClientName, action, itemName: name })).catch(() => {}); }
      }
      const execute = async (action: () => Promise<unknown>, after?: () => Promise<void>, recheck?: () => boolean) => {
        try {
          assertSession(); const result = await action();
          if (after) await after();
          assertSession(); if (recheck && !recheck()) throw new Error('Login not found or not allowed');
          return { content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
        } catch (error) { return { isError: true, content: [{ type: 'text' as const, text: assistantSafeError(error) }] }; }
      };
      const readAnnotations = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
      const writeAnnotations = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };
      mcp.registerTool('list_logins', { description: 'List allowed login names, websites, vault names, and tags. No secrets.', inputSchema: assistantSchemas.list_logins, annotations: readAnnotations }, async () => execute(() => engine.listAssistantLogins(token)));
      mcp.registerTool('get_login', { description: 'Retrieve username, password, and current TOTP for one allowed login. Ten calls per hour per agent.', inputSchema: assistantSchemas.get_login, annotations: readAnnotations }, async ({ name }) => { let fingerprint: string | null = null; return execute(() => { fingerprint = assistantItemFingerprint(engine, token, name); return engine.getAssistantLogin(token, name); }, () => notification('get', name), () => fingerprint !== null && assistantItemFingerprint(engine, token, name) === fingerprint); });
      mcp.registerTool('add_login', { description: 'Add a login in an allowed vault. Omitted password generates a strong password. Returns metadata only.', inputSchema: assistantSchemas.add_login, annotations: writeAnnotations }, async input => execute(() => engine.addAssistantLogin(token, input), () => notification('add', input.name)));
      mcp.registerTool('update_login', { description: 'Edit an allowed login. Replaced passwords are preserved in password history. Returns metadata only.', inputSchema: assistantSchemas.update_login, annotations: writeAnnotations }, async ({ name, fields }) => execute(() => engine.updateAssistantLogin(token, name, fields), () => notification('edit', fields.name || name)));
      mcp.registerTool('delete_login', { description: 'Move a login to Recently Deleted, restorable for thirty days. Never permanently deletes.', inputSchema: assistantSchemas.delete_login, annotations: { ...writeAnnotations, destructiveHint: true } }, async ({ name }) => execute(() => engine.deleteAssistantLogin(token, name), () => notification('delete', name)));
      mcp.registerTool('generate_password', { description: 'Generate a random password, memorable passphrase, or PIN. Does not store it.', inputSchema: assistantSchemas.generate_password, annotations: readAnnotations }, async ({ length, options: generation }) => execute(() => engine.generateAssistantPassword(token, { ...generation, ...(length === undefined ? {} : { length }) })));
      mcp.registerTool('search_items', { description: 'Search accessible item names and websites. No secrets.', inputSchema: assistantSchemas.search_items, annotations: readAnnotations }, async ({ query }) => execute(() => engine.searchAssistantItems(token, query)));
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      transports.add(transport);
      res.on('close', () => { transports.delete(transport); void transport.close(); void mcp.close(); });
      await mcp.connect(transport);
      if (req.method === 'POST') {
        const body = await readJson(req);
        const toolName = body.params?.name;
        if (engine.status().locked || engine.sessionVersion() !== sessionVersion) {
          if (body.method === 'tools/call' && recognizedTool(toolName)) await engine.auditAssistantAttempt(token, assistantActions[toolName], auditItemName(body), 'denied').catch(() => {});
          json(res, 423, { error: 'Vault is locked' }); return;
        }
        if (body.method === 'tools/call' && recognizedTool(toolName) && !assistantSchemas[toolName].safeParse(body.params?.arguments ?? {}).success) {
          await engine.auditAssistantAttempt(token, assistantActions[toolName], auditItemName(body), 'denied').catch(() => {});
        }
        await transport.handleRequest(req, res, body);
      } else await transport.handleRequest(req, res);
      return;
    }
    if (path === '/provider' && (!options.providerToken || !options.provider)) { json(res, 404, { ok: false, error: 'Not found' }); return; }
    const expected = path === '/provider' ? options.providerToken! : path === '/admin' ? options.adminToken : browserToken;
    if (!token || !tokenEqual(token, expected)) { json(res, 401, { ok: false, error: 'Unauthorized' }); return; }
    if (req.method !== 'POST') { json(res, 405, { ok: false, error: 'Method not allowed' }); return; }
    const body = await readJson(req);
    if ((path === '/browser' || path === '/provider') && engine.status().locked) { json(res, 423, { ok: false, error: 'Vault is locked' }); return; }
    const providerSession = path === '/provider' ? engine.data() : undefined;
    const result = path === '/provider' ? await options.provider!(body) : path === '/browser' ? await browserAction(engine, body) : await adminAction(engine, body);
    if (path === '/provider' && (engine.status().locked || engine.data() !== providerSession)) throw new Error('Vault is locked');
    json(res, 200, { ok: true, result });
  }
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(actualPort, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  actualPort = (server.address() as { port: number }).port;
  return { port: actualPort, browserToken, async close() { for (const transport of transports) await transport.close(); server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve())); } };
}
