/**
 * In-memory ring buffer of recent HTTP activity for the status-page console.
 *
 * Never stores Authorization headers, bodies, or other secrets — only method,
 * path, status, timing, and a short human message.
 */

export type ConsoleLevel = 'info' | 'warn' | 'error';

export interface ConsoleEntry {
  id: number;
  at: string;
  level: ConsoleLevel;
  method: string;
  path: string;
  statusCode: number;
  ms: number;
  ip: string;
  message: string;
}

type Listener = (entry: ConsoleEntry) => void;

const DEFAULT_CAPACITY = 200;

export class ConsoleLog {
  private readonly capacity: number;
  private readonly entries: ConsoleEntry[] = [];
  private readonly listeners = new Set<Listener>();
  private nextId = 1;

  constructor(capacity: number = DEFAULT_CAPACITY) {
    this.capacity = Math.max(10, capacity);
  }

  push( partial: Omit<ConsoleEntry, 'id' | 'at'> & { at?: string }): ConsoleEntry {
    const entry: ConsoleEntry = {
      id: this.nextId++,
      at: partial.at ?? new Date().toISOString(),
      level: partial.level,
      method: partial.method,
      path: partial.path,
      statusCode: partial.statusCode,
      ms: partial.ms,
      ip: partial.ip,
      message: partial.message,
    };
    this.entries.push(entry);
    if (this.entries.length > this.capacity) this.entries.shift();
    for (const listener of this.listeners) {
      try {
        listener(entry);
      } catch {
        // A broken subscriber must not break logging for others.
      }
    }
    return entry;
  }

  /** Newest-last snapshot for SSE replay / JSON export. */
  snapshot(): readonly ConsoleEntry[] {
    return this.entries.slice();
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  clear(): void {
    this.entries.length = 0;
  }
}

/** Classify a finished request for the console colour / tone. */
export function levelForStatus(statusCode: number): ConsoleLevel {
  if (statusCode >= 500) return 'error';
  if (statusCode >= 400) return 'warn';
  return 'info';
}

/** Short, secret-free summary of a finished request. */
export function summariseRequest(method: string, path: string, statusCode: number): string {
  const route = path.split('?')[0] ?? path;
  if (route === '/api/v1/health') return 'Health check';
  if (route === '/api/v1/prelogin') return 'Prelogin';
  if (route === '/api/v1/account' && method === 'POST') {
    if (statusCode === 201) return 'Account registered';
    if (statusCode === 409) return 'Account already exists';
    if (statusCode === 403) return 'Registration disabled';
    return 'Registration attempt';
  }
  if (route === '/api/v1/vault' && method === 'GET') {
    if (statusCode === 200) return 'Vault download';
    if (statusCode === 401) return 'Vault download unauthorized';
    if (statusCode === 429) return 'Vault download rate-limited';
    return 'Vault download';
  }
  if (route === '/api/v1/vault' && method === 'PUT') {
    if (statusCode === 200) return 'Vault upload';
    if (statusCode === 409) return 'Vault version conflict';
    if (statusCode === 401) return 'Vault upload unauthorized';
    if (statusCode === 429) return 'Vault upload rate-limited';
    return 'Vault upload';
  }
  if (route === '/api/v1/console') return 'Console stream';
  if (route === '/') return 'Status page';
  return `${method} ${route}`;
}

/** Paths we skip so the console watching itself does not flood the buffer. */
export function shouldLogPath(path: string): boolean {
  const route = path.split('?')[0] ?? path;
  return route !== '/api/v1/console' && route !== '/';
}
