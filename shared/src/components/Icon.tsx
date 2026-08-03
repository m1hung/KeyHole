/**
 * Icon set.
 *
 * Replaces the emoji placeholders the UI shipped with. Emoji rendered
 * differently on every OS, ignored `currentColor` so they never matched the
 * theme, and carried their own baked-in colour and metrics — none of which
 * belongs in a product whose whole surface is small monochrome affordances.
 *
 * `vault` is the Keyhole brand mark (filled rounded square with keyhole
 * cutout — `docs/brand/logo-mark.svg`). `key`, `generator`, `settings`,
 * `secureNote` and `localServer` are the supplied line artwork. The rest are
 * drawn to the same grammar so the set reads as one family:
 *
 *   24x24 viewBox · fill none · stroke currentColor · width 1.75 · round caps
 *
 * Anything added later must follow those five rules or it will look imported.
 */

import { useId, type ReactNode } from 'react';

export type IconName =
  // --- supplied artwork ---
  | 'vault'
  | 'key'
  | 'generator'
  | 'settings'
  | 'secureNote'
  | 'localServer'
  // --- drawn to match ---
  | 'copy'
  | 'check'
  | 'eye'
  | 'eyeOff'
  | 'lock'
  | 'user'
  | 'refresh'
  | 'chevronLeft'
  | 'clock'
  | 'plus'
  | 'trash';

const PATHS: Record<Exclude<IconName, 'vault'>, ReactNode> = {
  key: (
    <>
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M10.7 12.3 21 2" />
      <path d="m15.5 7.5 3 3L22 7l-3-3" />
    </>
  ),
  generator: (
    <>
      <path d="M19.5 8A8 8 0 0 0 5 6M5 3v3h3" />
      <path d="M4.5 16A8 8 0 0 0 19 18m0 3v-3h-3" />
      <path d="M12 8v8m-4-4h8m-6.8-2.8 5.6 5.6m0-5.6-5.6 5.6" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1.4 1.5v.1h-4v-.1A1.7 1.7 0 0 0 8.6 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.5-1H3v-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.5V3h4v.1A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.5 1h.1v4h-.1a1.7 1.7 0 0 0-1.5 1Z" />
    </>
  ),
  secureNote: (
    <>
      <path d="M6 3h8l4 4v4M14 3v4h4M13 21H6V3" />
      <rect x="12" y="14" width="9" height="7" rx="2" />
      <path d="M14.5 14v-1.5a2 2 0 0 1 4 0V14m-2 3.5v1" />
    </>
  ),
  localServer: (
    <>
      <rect x="4" y="4" width="16" height="6" rx="2" />
      <rect x="4" y="14" width="16" height="6" rx="2" />
      <path d="M8 7h.01m-.01 10h.01M12 7h5m-5 10h5m-5-7v4" />
    </>
  ),

  copy: (
    <>
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </>
  ),
  check: <path d="M20 6 9 17l-5-5" />,
  eye: (
    <>
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M10.6 5.1A9.9 9.9 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-2.6 3.6M6.6 6.6A17.2 17.2 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 4.5-1.1" />
      <path d="M14.1 14.1a3 3 0 1 1-4.2-4.2" />
      <path d="m2 2 20 20" />
    </>
  ),
  lock: (
    <>
      <rect x="3" y="11" width="18" height="10" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </>
  ),
  user: (
    <>
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </>
  ),
  refresh: (
    <>
      <path d="M21 12a9 9 0 0 1-15.4 6.4L3 16" />
      <path d="M3 12a9 9 0 0 1 15.4-6.4L21 8" />
      <path d="M21 3v5h-5M3 21v-5h5" />
    </>
  ),
  chevronLeft: <path d="m15 18-6-6 6-6" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  trash: (
    <>
      <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
      <path d="M10 11v6M14 11v6" />
    </>
  ),
};

interface IconProps {
  name: IconName;
  /** Edge length in px. 20 suits inline buttons, 24 the tab bar. */
  size?: number;
  className?: string;
  /**
   * Accessible name. Omit when a visible label or the parent button's
   * title/aria-label already names the control — otherwise screen readers
   * announce it twice.
   */
  title?: string;
}

export function Icon({ name, size = 20, className, title }: IconProps) {
  const rawId = useId();
  // Colons from React's useId break `url(#…)` mask references in some engines.
  const maskId = `kh-mark-${rawId.replace(/:/g, '')}`;
  const a11y = title ? { role: 'img' as const } : { 'aria-hidden': true as const };

  if (name === 'vault') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        className={className}
        focusable="false"
        {...a11y}
      >
        {title ? <title>{title}</title> : null}
        <defs>
          <mask id={maskId}>
            <rect width="64" height="64" fill="white" />
            <circle cx="32" cy="25" r="8" fill="black" />
            <path d="M28.5 30.5 24 48h16l-4.5-17.5Z" fill="black" />
          </mask>
        </defs>
        <rect x="4" y="4" width="56" height="56" rx="15" fill="currentColor" mask={`url(#${maskId})`} />
      </svg>
    );
  }

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      // `focusable` stops IE/legacy Edge putting SVGs in the tab order; harmless
      // elsewhere and cheap insurance.
      focusable="false"
      {...a11y}
    >
      {title ? <title>{title}</title> : null}
      {PATHS[name]}
    </svg>
  );
}
