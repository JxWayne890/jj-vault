export interface BrowserItem {
  id: string;
  title: string;
  type: string;
  username?: string;
  password?: string;
  urls?: string[];
  /** Current one time code only. The TOTP seed never enters the extension. */
  totp?: string;
  fields?: { label: string; value: string; kind?: string; section?: string }[];
}

export interface LoginCandidate {
  url: string;
  title: string;
  username: string;
  password: string;
  capturedAt: number;
}

export interface ExtensionAPI {
  runtime: {
    id: string;
    lastError?: { message?: string };
    sendNativeMessage(name: string, message: unknown): Promise<{ ok: boolean; result?: any; error?: string }>;
    sendMessage(message: unknown): Promise<any>;
    onMessage: { addListener(handler: (message: any, sender: any, respond: (value: any) => void) => boolean | void): void };
  };
  tabs: {
    query(query: unknown): Promise<{ id?: number; url?: string; title?: string }[]>;
    get(id: number): Promise<{ id?: number; url?: string }>;
    sendMessage(id: number, message: unknown, options?: { frameId: number }): Promise<any>;
    onRemoved: { addListener(handler: (id: number) => void): void };
    onUpdated?: { addListener(handler: (id: number, change: { url?: string }) => void): void };
  };
  action: {
    /** Supported in Chrome 127 and newer. Older browsers use the toolbar instruction. */
    openPopup?: () => Promise<void>;
    setBadgeText(options: { tabId: number; text: string }): Promise<void>;
    setBadgeBackgroundColor(options: { tabId: number; color: string }): Promise<void>;
  };
}

export const extensionAPI = (): ExtensionAPI => {
  const environment = globalThis as any;
  return environment.browser ?? environment.chrome;
};
