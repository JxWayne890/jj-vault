export type ItemType = 'login'|'password'|'creditCard'|'bankAccount'|'identity'|'secureNote'|'document'|'softwareLicense'|'apiCredential'|'sshKey'|'passport'|'driversLicense'|'wifi'|'membership'|'cryptoWallet'|'passkey'|'xMoney';
export const ITEM_TYPES: ItemType[] = ['login','password','creditCard','bankAccount','identity','secureNote','document','softwareLicense','apiCredential','sshKey','passport','driversLicense','wifi','membership','cryptoWallet','passkey','xMoney'];
export interface Field {id:string;label:string;value:string;kind:'text'|'password'|'url'|'date'|'email'|'phone';section?:string}
export interface Vault {id:string;name:string;allowAssistant:boolean;allowBrowser:boolean;travelSafe:boolean}
export interface Item {id:string;vaultId:string;type:ItemType;title:string;username?:string;password?:string;urls:string[];totp?:string;notes?:string;fields:Field[];sections?:string[];tags:string[];favorite:boolean;archived:boolean;deletedAt?:string;restoreUntil?:string;restoredAt?:string;createdAt:string;updatedAt:string;passwordHistory:{password:string;changedAt:string}[];allowAssistant:boolean;expiresAt?:string;attachments:{id:string;name:string;mime:string;data:string}[];passkey?:{credentialId:string;rpId:string;userHandle:string;userName:string;privateKey:string;publicKey:string;signCount:number;backedUp?:boolean}}
export interface Activity {id:string;at:string;action:string;itemId?:string;itemName?:string;detail?:string;agentId?:string;agentClientName?:string;agentName?:string;outcome?:'success'|'denied'|'rate_limited'}
export type AgentPermission = 'read'|'read_add'|'read_add_edit'|'full';
export const AGENT_PERMISSIONS:AgentPermission[] = ['read','read_add','read_add_edit','full'];
export interface AgentOptions {clientName?:string;permission?:AgentPermission;vaultIds?:string[]}
export interface AgentUpdate {name?:string;permission?:AgentPermission;vaultIds?:string[]}
export interface AssistantLoginInput {vault:string;name:string;website:string;username:string;password?:string;notes?:string;totp_secret?:string;tags?:string[]}
export type AssistantLoginFields = Partial<Omit<AssistantLoginInput,'vault'>>;
export interface AssistantLoginSummary {name:string;website:string;vault:string;tags:string[]}
export interface AssistantDeletion {name:string;deleted:true;restoreUntil:string}
export interface TokenRecord {id:string;name:string;hash:string;createdAt:string;revokedAt?:string;calls:number[];clientName:string;permission:AgentPermission;vaultIds:string[];writeCalls:number[]}
export interface VaultData {schema:1;deviceId:string;vaults:Vault[];items:Item[];activity:Activity[];settings:{
  /** Minutes before automatic locking. Zero disables automatic locking (Never). */
  idleMinutes:number;travelMode:boolean;notifyAssistant:boolean;agentRequireItemApproval?:boolean
};assistantTokens:TokenRecord[];revision:number}
export interface Envelope {format:'jjvault';version:1;id:string;kdf:{algorithm:'argon2id';salt:string;memoryKiB:number;iterations:number;parallelism:number};iv:string;ciphertext:string}
export interface VaultStorage {read():Promise<Envelope|null>;write(envelope:Envelope):Promise<void>}
export interface Finding {itemId:string;title:string;kind:'weak'|'reused'|'breached'|'missing2fa'|'expiring'|'http';detail:string}
export interface WatchtowerReport {score:number;findings:Finding[];checked:number;breachCheck:'notRequested'|'complete'|'partial';errors:string[]}
