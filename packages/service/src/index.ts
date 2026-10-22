export { startLocalService, type LocalServiceOptions } from './local-service.ts';
export { startSyncServer, runSyncServer, type ShareEnvelope } from './sync-server.ts';
export { syncVault, createShare, openShare, revokeShare } from './clients.ts';
export { randomToken, atomicOwnerWrite, readOwnerFile } from './security.ts';

export { createPasskeyProvider } from './passkeys.ts';
