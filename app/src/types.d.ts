/**
 * File System Access API typings.
 *
 * TypeScript's DOM lib does not yet include these, and we only use a small
 * slice of the API, so a narrow local declaration beats pulling in another
 * dependency.
 */

interface FileSystemHandlePermissionDescriptor {
  mode?: 'read' | 'readwrite';
}

interface FileSystemFileHandle {
  queryPermission?(descriptor?: FileSystemHandlePermissionDescriptor): Promise<PermissionState>;
  requestPermission?(descriptor?: FileSystemHandlePermissionDescriptor): Promise<PermissionState>;
}

interface FilePickerAcceptType {
  description?: string;
  accept: Record<string, string[]>;
}

interface SaveFilePickerOptions {
  suggestedName?: string;
  types?: FilePickerAcceptType[];
}

interface OpenFilePickerOptions {
  types?: FilePickerAcceptType[];
  multiple?: boolean;
}

declare function showSaveFilePicker(options?: SaveFilePickerOptions): Promise<FileSystemFileHandle>;
declare function showOpenFilePicker(options?: OpenFilePickerOptions): Promise<FileSystemFileHandle[]>;

/**
 * Install-prompt typings.
 *
 * `beforeinstallprompt` is Chromium-only and not in the DOM lib, so the same
 * narrow-declaration rule as above applies. Consumers must still treat it as
 * possibly-absent at runtime — Firefox and Safari never fire it.
 */
interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
  prompt(): Promise<void>;
}

interface WindowEventMap {
  beforeinstallprompt: BeforeInstallPromptEvent;
  appinstalled: Event;
}

/**
 * The Electron preload bridge (desktop/src/preload.cjs).
 *
 * Absent in the browser build, which is exactly how the app detects which one it
 * is running as — so this is declared optional at every use site rather than
 * assumed. Only encrypted envelopes as JSON text cross this boundary; there is
 * deliberately no member here that could carry a key or a password.
 */
interface KeyholeDesktopBridge {
  readonly desktop: true;
  readonly platform: string;
  readonly vault: {
    read(): Promise<string | null>;
    write(json: string): Promise<boolean>;
    clear(): Promise<boolean>;
    path(): Promise<string>;
    reveal(): Promise<boolean>;
    importFile(): Promise<string | null>;
    exportFile(json: string): Promise<string | null>;
  };
}
