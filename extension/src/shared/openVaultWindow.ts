/**
 * Open the full vault UI in a detached popup window (not a browser tab).
 *
 * Chrome's action popup is capped at a small size and `openOptionsPage()` with
 * `open_in_tab: true` steals a tab. A `type: 'popup'` window is the middle
 * ground: large enough for the options UI, still clearly an extension surface.
 */

const WINDOW_ID_KEY = 'keyhole.vaultWindowId';

const WINDOW_WIDTH = 880;
const WINDOW_HEIGHT = 640;

export async function openVaultWindow(): Promise<void> {
  const stored = await chrome.storage.session.get(WINDOW_ID_KEY);
  const existingId = stored[WINDOW_ID_KEY];

  if (typeof existingId === 'number') {
    try {
      await chrome.windows.update(existingId, { focused: true });
      return;
    } catch {
      // Window was closed; fall through and open a new one.
      await chrome.storage.session.remove(WINDOW_ID_KEY);
    }
  }

  const created = await chrome.windows.create({
    url: chrome.runtime.getURL('options.html'),
    type: 'popup',
    width: WINDOW_WIDTH,
    height: WINDOW_HEIGHT,
    focused: true,
  });

  if (typeof created?.id === 'number') {
    await chrome.storage.session.set({ [WINDOW_ID_KEY]: created.id });
  }
}
