import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import { initVaultStore } from './storage.ts';
import './styles.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root container missing.');

/**
 * Hydrate the vault store before the first render.
 *
 * On desktop the vault is a file read over IPC, which is asynchronous. Mounting
 * first would render the create-vault screen for a frame or two at someone who
 * already has a vault — indistinguishable, from the user's side, from having
 * lost it. One await removes that class of scare entirely.
 */
const init = await initVaultStore();

createRoot(container).render(
  <StrictMode>
    <App legacyBrowserVaultAvailable={init.legacyBrowserVaultAvailable} />
  </StrictMode>,
);
