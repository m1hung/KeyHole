/**
 * The entire trust boundary between the renderer and the machine.
 *
 * CommonJS, not ESM, on purpose: sandboxed preload scripts do not support ESM,
 * and `sandbox: true` is worth more than file-extension consistency.
 *
 * Everything below is a thin, argument-free-or-string-only wrapper over an IPC
 * channel that main validates. There is no `fs`, no `child_process`, no
 * `ipcRenderer` itself — the renderer gets seven verbs and nothing more, so the
 * worst a renderer compromise can do to the disk is write a JSON blob to one
 * known path or open a file dialog the user must click through.
 *
 * Note what is *not* here: nothing that takes the master password, a key, or
 * decrypted data. Encryption happens entirely in the renderer, and only the
 * sealed envelope crosses this line.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('keyhole', {
  /** Presence of this object is how the renderer detects the desktop build. */
  desktop: true,
  platform: process.platform,

  vault: {
    /** The stored envelope as JSON text, or null when no vault exists yet. */
    read: () => ipcRenderer.invoke('vault:read'),
    /** Atomically replace the stored envelope. Resolves once it is on disk. */
    /** @param {string} json */
    write: (json) => ipcRenderer.invoke('vault:write', json),
    /** Delete the vault file, keeping one .bak generation. */
    clear: () => ipcRenderer.invoke('vault:clear'),
    /** Absolute path of the vault file, for display in Settings. */
    path: () => ipcRenderer.invoke('vault:path'),
    /** Show the vault file in Explorer. */
    reveal: () => ipcRenderer.invoke('vault:reveal'),
    /** Native open dialog; resolves to file contents, or null if cancelled. */
    importFile: () => ipcRenderer.invoke('vault:import'),
    /** Native save dialog; resolves to the written path, or null if cancelled. */
    /** @param {string} json */
    exportFile: (json) => ipcRenderer.invoke('vault:export', json),
  },
});
