/**
 * Public surface of @keyhole/shared.
 *
 * Sync HTTP client, shared React UI primitives, and copy used by both the
 * desktop renderer and the browser extension. Persistence and session state
 * stay in each product.
 */

export {
  SyncClientError,
  healthCheck,
  fetchPrelogin,
  registerAccount,
  getVault,
  putVault,
  type SyncConfig,
  type RegisterResult,
  type VaultRemote,
  type PutVaultResult,
  type PutVaultResponse,
} from './sync/client.ts';

export {
  performSync,
  rotateSyncAuthAfterRekey,
  type PerformSyncParams,
  type PerformSyncResult,
  type RotateSyncAuthParams,
} from './sync/runSync.ts';

export { copy } from './copy.ts';
export { checkPasswordBreachCount } from './breach/check.ts';

export { Icon, type IconName } from './components/Icon.tsx';
export {
  FINDINGS_PAGE,
  SecretField,
  StrengthMeter,
  ConfirmDialog,
  Toast,
  EmptyState,
} from './components/common.tsx';
export { GeneratorPanel } from './components/GeneratorPanel.tsx';
export { GeneratorOptionsForm } from './components/GeneratorOptionsForm.tsx';
