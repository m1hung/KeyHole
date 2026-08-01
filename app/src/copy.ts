/**
 * Canonical user-facing copy shared by the desktop app and the Chrome extension.
 *
 * iOS mirrors these phrases as string literals (no TS import). When you change a
 * string here, update the matching iOS views in the same change.
 */

import { TRASH_RETENTION_DAYS } from '@keyhole/core';

export const copy = {
  unlockSubtitle: 'Your vault is locked.',

  moveToTrash: 'Move to trash',
  deleteForever: 'Delete forever',
  removePasskey: 'Remove passkey',

  authenticatorSection: 'Authenticator',
  authenticatorField: 'Authenticator key or otpauth:// URI',

  passkeysSection: 'Passkeys',
  passkeysHint: 'Created on iPhone. Sign in with Safari or iOS AutoFill.',
  passkeyBadge: 'passkey',
  passkeyTitle: 'Passkey — use Safari or iOS AutoFill to sign in',
  passkeyFillHint: 'Password fill only — passkeys require Safari or iOS AutoFill',

  trashRetention: `Deleted entries appear here for ${TRASH_RETENTION_DAYS} days.`,
  trashRemovedAfter: `removed for good after ${TRASH_RETENTION_DAYS} days`,

  syncRegister: 'Register & upload',
  syncNow: 'Sync now',
  syncWorking: 'Working…',
  syncSyncing: 'Syncing…',
} as const;
