/**
 * Browser landing page for the sync server.
 *
 * Mirrors the web app's unlock-screen card: same tokens, type, radii, and the
 * brand mark / local-server icons so opening :8787 feels like Keyhole rather
 * than a bare Fastify 404. Includes a live SSE console of recent API activity.
 *
 * The page is sized to the viewport and never scrolls as a document — only the
 * console scrolls, because a log is the one thing here that is unbounded.
 * Everything else scales with `vmin` so a short window shrinks the type rather
 * than pushing content off the bottom.
 */

import type { AccountSummary } from './db.ts';

export interface StatusPageProps {
  port: number;
  accounts: number;
  allowRegistration: boolean;
  /**
   * Origin the browser actually used, when known — `127.0.0.1` is wrong to
   * display to someone who reached this page across a network.
   */
  origin?: string | undefined;
  /**
   * Control-plane details, present only when this page is being served to a
   * direct loopback request. Everything here is a capability: rendering it for
   * a remote viewer would hand them a shutdown switch, so the decision is made
   * by the caller in app.ts, not here.
   */
  control?: { token: string; port: number; allowRegistration: boolean } | undefined;
  /** Seconds since boot. The page ticks it forward itself rather than polling. */
  uptimeSeconds?: number | undefined;
  /**
   * Details about the host process. Gated the same way as `control`: none of it
   * is a capability, but a process id and an absolute path on disk are things a
   * remote viewer of an unauthenticated page has no business collecting.
   */
  machine?:
    | { pid: number; databasePath: string; databaseBytes?: number | undefined }
    | undefined;
  /**
   * Enrolled accounts. Gated identically to `machine` — account ids are the
   * only user-identifying data the server holds, and an unauthenticated page
   * reachable over a tailnet is not the place to publish them.
   */
  roster?: readonly AccountSummary[] | undefined;
}

/** "3m ago", "2d ago" — absolute timestamps are noise at this size. */
function relativeTime(iso: string, now: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '—';
  const secs = Math.max(0, Math.round((now - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/** The origin comes from a request header, so it is attacker-controlled text. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function renderStatusPage({
  port,
  accounts,
  allowRegistration,
  origin,
  control,
  uptimeSeconds,
  machine,
  roster,
}: StatusPageProps): string {
  const registration = allowRegistration ? 'Open' : 'Closed';
  const registrationClass = allowRegistration ? 'warn' : 'ok';
  const serverUrl = escapeHtml(origin ?? `http://127.0.0.1:${port}`);

  // Machine rows follow the same rule as the controls: absent entirely for a
  // remote viewer rather than blanked out, so the page does not advertise that
  // there is something it is not showing them.
  const machineRows = machine
    ? `
          <div class="row"><span>Process</span><b>${machine.pid}</b></div>
          <div class="row"><span>Database</span><b>${
            machine.databaseBytes === undefined ? '—' : escapeHtml(formatBytes(machine.databaseBytes))
          }</b></div>
          <div class="row path" title="${escapeHtml(machine.databasePath)}"><span>Path</span><b>${escapeHtml(
            machine.databasePath,
          )}</b></div>`
    : '';

  const now = Date.now();
  const rosterSection =
    roster && roster.length > 0
      ? `
      <div class="block">
        <p class="section-label">Accounts (${roster.length})</p>
        <div class="rows roster">${roster
          .map(
            (a) => `
          <div class="row" title="created ${escapeHtml(a.createdAt)}"><span>${escapeHtml(
            a.accountId,
          )}</span><b>${escapeHtml(relativeTime(a.updatedAt, now))} · v${a.version} · ${escapeHtml(
              formatBytes(a.envelopeBytes),
            )}</b></div>`,
          )
          .join('')}
        </div>
      </div>`
      : '';

  const controlSection = control
    ? `
        <div class="block controls-block">
          <p class="section-label">Server controls</p>
          <div class="controls">
            <button type="button" id="registration-btn">${
              control.allowRegistration ? 'Close registration' : 'Open registration'
            }</button>
            <button type="button" id="backup-btn">Download backup</button>
            <button type="button" id="restart-btn">Restart</button>
            <button type="button" id="stop-btn" class="danger">Stop</button>
          </div>
          <p id="control-msg">Local session — these act on this machine.</p>
        </div>`
    : '';

  // JSON.stringify, not interpolation: these end up inside a script element,
  // and it is the escaping that makes that safe rather than the values
  // happening to be a number and base64url today.
  const controlScript = control
    ? `
      (function () {
        const base = "http://127.0.0.1:" + ${JSON.stringify(control.port)};
        const token = ${JSON.stringify(control.token)};
        const msg = document.getElementById("control-msg");
        const restartBtn = document.getElementById("restart-btn");
        const stopBtn = document.getElementById("stop-btn");

        function say(text, isError) {
          msg.textContent = text;
          msg.classList.toggle("err", Boolean(isError));
        }

        async function send(action) {
          restartBtn.disabled = true;
          stopBtn.disabled = true;
          say(action === "stop" ? "Stopping…" : "Restarting…", false);
          try {
            const res = await fetch(base + "/control/v1/" + action, {
              method: "POST",
              headers: { Authorization: "Bearer " + token },
            });
            if (!res.ok) throw new Error("HTTP " + res.status);
            if (action === "stop") {
              say("Stopped. Start it again from the Keyhole Sync Server icon.", false);
              return;
            }
            // The server is going away and coming back, so poll rather than
            // assuming a fixed pause is long enough.
            for (let i = 0; i < 50; i++) {
              await new Promise((r) => setTimeout(r, 300));
              try {
                const health = await fetch("/api/v1/health", { cache: "no-store" });
                if (health.ok) {
                  location.reload();
                  return;
                }
              } catch {}
            }
            say("Restarted, but it has not answered yet. Check the logs.", true);
          } catch (err) {
            say("Failed: " + err.message, true);
            restartBtn.disabled = false;
            stopBtn.disabled = false;
          }
        }

        const registrationBtn = document.getElementById("registration-btn");
        let registrationOpen = ${JSON.stringify(control.allowRegistration)};

        registrationBtn.addEventListener("click", async () => {
          const next = !registrationOpen;
          // Confirm on open only. Closing is the safe direction and should cost
          // one click; opening exposes account creation to anyone who can reach
          // the server.
          if (next && !confirm("Open registration? Anyone who can reach this server will be able to create an account on it.")) {
            return;
          }
          registrationBtn.disabled = true;
          say(next ? "Opening…" : "Closing…", false);
          try {
            const res = await fetch(base + "/control/v1/registration", {
              method: "POST",
              headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
              body: JSON.stringify({ allow: next }),
            });
            if (!res.ok) throw new Error("HTTP " + res.status);
            const data = await res.json();
            registrationOpen = data.allowRegistration;

            // Update in place rather than reloading: a reload would discard the
            // console history and any filters the reader had set. The restart
            // handler only gets away with reloading because the server actually
            // went away.
            registrationBtn.textContent = registrationOpen ? "Close registration" : "Open registration";
            const tile = document.getElementById("registration-value");
            if (tile) {
              tile.textContent = registrationOpen ? "Open" : "Closed";
              tile.className = "v " + (registrationOpen ? "warn" : "ok");
            }
            say(
              data.persisted
                ? (registrationOpen ? "Registration open." : "Registration closed.")
                : (registrationOpen ? "Open for now" : "Closed for now") + " — could not save to disk, so it reverts on restart.",
              !data.persisted,
            );
          } catch (err) {
            say("Failed: " + err.message, true);
          } finally {
            registrationBtn.disabled = false;
          }
        });

        const backupBtn = document.getElementById("backup-btn");
        backupBtn.addEventListener("click", async () => {
          // Cannot be a plain <a download>: the route needs an Authorization
          // header, which only fetch can set.
          backupBtn.disabled = true;
          const label = backupBtn.textContent;
          backupBtn.textContent = "Preparing…";
          // VACUUM blocks the server for the duration, so an unresponsive
          // button here would read as a hang rather than as work in progress.
          say("Snapshotting the vault database…", false);
          try {
            const res = await fetch(base + "/control/v1/backup", {
              headers: { Authorization: "Bearer " + token },
            });
            if (!res.ok) throw new Error("HTTP " + res.status);
            const blob = await res.blob();
            // Filename built here rather than read from Content-Disposition,
            // which would need Access-Control-Expose-Headers on a deliberately
            // minimal CORS surface.
            const stamp = new Date().toISOString().replace(/[:.]/g, "-");
            download(blob, "keyhole-backup-" + stamp + ".sqlite");
            say("Backup downloaded (" + Math.max(1, Math.round(blob.size / 1024)) + " KB).", false);
          } catch (err) {
            say("Backup failed: " + err.message, true);
          } finally {
            backupBtn.disabled = false;
            backupBtn.textContent = label;
          }
        });

        restartBtn.addEventListener("click", () => send("restart"));
        stopBtn.addEventListener("click", () => {
          // Stopping ends sync for every device, and nothing on a web page can
          // undo it — the way back is the desktop icon or systemctl.
          if (confirm("Stop the Keyhole sync server? Other devices will not be able to sync until it is started again.")) {
            send("stop");
          }
        });
      })();`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="light dark" />
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='32' height='32' viewBox='0 0 64 64'%3E%3Cdefs%3E%3Cmask id='k'%3E%3Crect width='64' height='64' fill='white'/%3E%3Ccircle cx='32' cy='25' r='8' fill='black'/%3E%3Cpath d='M28.5 30.5 24 48h16l-4.5-17.5Z' fill='black'/%3E%3C/mask%3E%3C/defs%3E%3Crect x='4' y='4' width='56' height='56' rx='15' fill='%2320242b' mask='url(%23k)'/%3E%3C/svg%3E" />
  <title>Keyhole sync</title>
  <style>
    :root {
      --bg: light-dark(#f4f6f8, #0d1117);
      --surface: light-dark(#ffffff, #151b23);
      --surface-2: light-dark(#e9edf2, #1e262f);
      --border: light-dark(#d7dee6, #2a3341);
      --text: light-dark(#0f172a, #e6edf3);
      --text-dim: light-dark(#57646f, #8b97a6);
      --accent: light-dark(#0f62d0, #4d9fff);
      --accent-soft: light-dark(#e7f0fd, #14243a);
      --ok: light-dark(#067647, #3fb950);
      --warn: light-dark(#b54708, #d29922);
      --danger: light-dark(#b42318, #ff7b72);
      --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      --ease-out: cubic-bezier(0.16, 1, 0.3, 1);

      /* Everything below scales with vmin. Height is what actually runs out
         first, but pure vh makes an ultrawide window absurd, so the smaller
         axis drives it and clamp() keeps both extremes sane. */
      --gap: clamp(7px, 1.3vmin, 15px);
      --pad: clamp(11px, 2vmin, 22px);
      --radius: clamp(9px, 1.4vmin, 13px);
      --fs-body: clamp(11px, 1.62vmin, 14px);
      --fs-small: clamp(9.5px, 1.36vmin, 12px);
      --fs-tiny: clamp(8.5px, 1.2vmin, 11px);
      --fs-mono: clamp(9.5px, 1.3vmin, 12.5px);
      --fs-h1: clamp(16px, 2.9vmin, 26px);
      --fs-stat: clamp(14px, 2.3vmin, 21px);

      --shadow: light-dark(0 1px 2px rgb(15 23 42 / 8%), 0 1px 2px rgb(0 0 0 / 50%)),
                light-dark(0 8px 24px -6px rgb(15 23 42 / 12%), 0 8px 24px -6px rgb(0 0 0 / 45%));
      color-scheme: light dark;
    }

    * { box-sizing: border-box; }

    html, body {
      height: 100%;
      margin: 0;
      /* The document itself must never scroll — that is the whole point of the
         grid below. Only #console does. */
      overflow: hidden;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font: var(--fs-body)/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }

    /* dvh, not vh: on mobile the URL bar makes vh taller than what you can
       actually see, which would reintroduce the scroll this exists to remove. */
    .shell {
      height: 100dvh;
      display: grid;
      gap: var(--gap);
      padding: var(--gap);
      grid-template-columns: 1fr;
      /* minmax(0, auto) rather than auto: the info row is sized to its content
         when there is room, but may shrink below it when there is not — with
         .info scrolling internally — so the console keeps a floor it can
         actually be read in. A plain auto row refuses to shrink and squeezes
         the console to a couple of lines on a phone. */
      grid-template-rows: minmax(0, auto) minmax(clamp(96px, 20vh, 220px), 1fr);
      animation: fade-in 300ms var(--ease-out) both;
    }

    @media (min-width: 860px) {
      .shell {
        grid-template-columns: minmax(270px, 25vw) minmax(0, 1fr);
        grid-template-rows: minmax(0, 1fr);
      }
    }

    @keyframes fade-in {
      from { opacity: 0; transform: translateY(6px); }
      to   { opacity: 1; transform: none; }
    }

    @media (prefers-reduced-motion: reduce) {
      .shell { animation-duration: 1ms; }
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      min-height: 0;
    }

    /* The info panel scrolls internally only if a viewport is so short that
       nothing legible would fit. Content is never clipped; the page still does
       not scroll. */
    .info {
      padding: var(--pad);
      display: flex;
      flex-direction: column;
      gap: var(--gap);
      overflow: auto;
      overscroll-behavior: contain;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: clamp(6px, 1vmin, 10px);
      font-size: var(--fs-h1);
      font-weight: 600;
      margin: 0;
      letter-spacing: -0.01em;
    }

    .brand svg { color: var(--accent); flex: none; width: 1.05em; height: 1.05em; }

    .subtitle {
      color: var(--text-dim);
      margin: calc(var(--gap) * -0.6) 0 0;
      font-size: var(--fs-small);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      align-self: flex-start;
      padding: 4px 9px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: var(--fs-tiny);
      font-weight: 500;
      margin: 0;
    }

    .badge svg { flex: none; }

    /* Two columns of stats rather than four stacked rows: the same information
       in roughly half the height, which is the budget that matters here. */
    .stats {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: calc(var(--gap) * 0.6);
      margin: 0;
    }

    /* An odd tile count would otherwise leave a half-width orphan on the last
       row. Let it span instead, in both the 2-column and 4-column layouts. */
    .stat:last-child:nth-child(odd) { grid-column: 1 / -1; }

    .stat {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: calc(var(--radius) * 0.75);
      padding: calc(var(--pad) * 0.42) calc(var(--pad) * 0.5);
      min-width: 0;
    }

    .stat .k {
      display: block;
      color: var(--text-dim);
      font-size: var(--fs-tiny);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .stat .v {
      display: block;
      font-size: var(--fs-stat);
      font-weight: 600;
      line-height: 1.2;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .ok { color: var(--ok); }
    .warn { color: var(--warn); }

    .block { display: flex; flex-direction: column; gap: calc(var(--gap) * 0.5); min-width: 0; }

    .section-label {
      margin: 0;
      font-size: var(--fs-tiny);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-dim);
    }

    .url-row {
      display: flex;
      gap: calc(var(--gap) * 0.5);
      align-items: stretch;
      min-width: 0;
    }

    .url-row code {
      flex: 1;
      min-width: 0;
      padding: calc(var(--pad) * 0.35) calc(var(--pad) * 0.45);
      border-radius: calc(var(--radius) * 0.7);
      border: 1px solid var(--border);
      background: var(--surface-2);
      font-family: var(--mono);
      font-size: var(--fs-mono);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      display: flex;
      align-items: center;
    }

    button {
      font: inherit;
      font-size: var(--fs-small);
      font-weight: 600;
      cursor: pointer;
      border-radius: calc(var(--radius) * 0.7);
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--text);
      padding: calc(var(--pad) * 0.3) calc(var(--pad) * 0.55);
      white-space: nowrap;
    }

    button:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    button:disabled { opacity: 0.55; cursor: default; }

    .steps {
      margin: 0;
      padding-left: 1.25em;
      color: var(--text-dim);
      font-size: var(--fs-small);
      display: grid;
      gap: 1px;
    }

    .rows { display: grid; gap: 1px; min-width: 0; }

    /* Scrolls on its own rather than pushing the stop/restart block — which
       sits after the spacer — below the fold on a laptop. */
    .roster {
      max-height: clamp(90px, 22vh, 260px);
      overflow: auto;
      overscroll-behavior: contain;
    }

    .roster .row b { font-weight: 500; color: var(--text-dim); font-size: var(--fs-tiny); }
    .roster .row span { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .row {
      display: flex;
      justify-content: space-between;
      gap: var(--gap);
      font-size: var(--fs-small);
      min-width: 0;
    }

    .row span { color: var(--text-dim); flex: none; }
    .row b { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row.path b { font-family: var(--mono); font-size: var(--fs-tiny); direction: rtl; text-align: left; }

    .links {
      display: flex;
      flex-wrap: wrap;
      gap: calc(var(--gap) * 0.5);
      font-size: var(--fs-tiny);
    }

    .links a {
      color: var(--accent);
      text-decoration: none;
      font-family: var(--mono);
      padding: 2px 7px;
      border: 1px solid var(--border);
      border-radius: 999px;
    }

    .links a:hover { border-color: var(--accent); }

    .controls { display: flex; gap: calc(var(--gap) * 0.5); flex-wrap: wrap; }

    /* Stopping ends vault sync for every device, so it should not look like
       the same weight of action as restarting. */
    .controls button.danger:hover:not(:disabled) { border-color: var(--danger); color: var(--danger); }

    #control-msg {
      font-size: var(--fs-tiny);
      color: var(--text-dim);
      margin: 0;
      min-height: 1.2em;
    }

    #control-msg.err { color: var(--danger); }

    .hint { margin: 0; color: var(--text-dim); font-size: var(--fs-tiny); }

    /* Pushes the controls to the bottom of the panel when there is room to
       spare, and collapses to nothing when there is not. */
    .spacer { flex: 1 1 0; min-height: 0; }

    .console-card {
      display: flex;
      flex-direction: column;
      overflow: hidden;
      min-height: 0;
    }

    .console-header {
      display: flex;
      align-items: center;
      gap: calc(var(--gap) * 0.6);
      flex-wrap: wrap;
      padding: calc(var(--pad) * 0.4) calc(var(--pad) * 0.55);
      border-bottom: 1px solid var(--border);
      flex: none;
    }

    .console-header h2 {
      margin: 0 auto 0 0;
      font-size: var(--fs-tiny);
      font-weight: 600;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      color: var(--text-dim);
    }

    .live {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      color: var(--ok);
      font-weight: 600;
      font-size: var(--fs-tiny);
    }

    .live[data-state="offline"] { color: var(--danger); }

    .live::before {
      content: "";
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 0 3px color-mix(in srgb, currentColor 22%, transparent);
    }

    .console-header input, .console-header select {
      font: inherit;
      font-size: var(--fs-tiny);
      color: var(--text);
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: calc(var(--radius) * 0.6);
      padding: 3px 7px;
      min-width: 0;
    }

    .console-header input { width: clamp(80px, 14vmin, 150px); }
    .console-header input:focus, .console-header select:focus { outline: 1px solid var(--accent); }

    #count { color: var(--text-dim); font-size: var(--fs-tiny); font-variant-numeric: tabular-nums; }

    #console {
      flex: 1;
      min-height: 0;
      margin: 0;
      padding: calc(var(--pad) * 0.35) calc(var(--pad) * 0.5);
      overflow: auto;
      overscroll-behavior: contain;
      background: light-dark(#0f1419, #0a0e14);
      color: light-dark(#d5dde6, #c8d1dc);
      font-family: var(--mono);
      font-size: var(--fs-mono);
      line-height: 1.5;
      white-space: pre;
    }

    #console:empty::before {
      content: "Waiting for activity…";
      color: var(--text-dim);
    }

    .log-line {
      display: grid;
      grid-template-columns: 6.2em 3.2em 3.6em minmax(0, 1fr);
      gap: clamp(4px, 0.8vmin, 10px);
      padding: 1px 0;
      border-bottom: 1px solid rgb(255 255 255 / 4%);
    }

    .log-line .time { color: #7f8b99; }
    .log-line .status { font-weight: 600; }
    .log-line .ms { color: #7f8b99; text-align: right; }
    .log-line .msg { color: inherit; overflow: hidden; text-overflow: ellipsis; }

    .log-line.info .status { color: #5b9fd4; }
    .log-line.warn .status { color: #d29922; }
    .log-line.error .status { color: #ff7b72; }

    /* Very short windows: drop the prose, keep the data. vmin has already
       bottomed out on its clamp floor by this point, so the spacing floors
       have to come down too or the panel overflows by a few pixels. */
    @media (max-height: 560px) {
      :root {
        --gap: clamp(5px, 1.3vmin, 10px);
        --pad: clamp(8px, 2vmin, 15px);
      }
      .subtitle, .steps, .hint { display: none; }
    }

    /* Shorter still: the badge is reassurance, not information. */
    @media (max-height: 450px) {
      .badge { display: none; }
      .stats { grid-template-columns: repeat(4, 1fr); }
    }

    /* Phones: the panel and the console are stacked and both want the same
       pixels. The prose is the part that survives being dropped — and with the
       roster present, so are the endpoint shortcuts, which are two links anyone
       can type. Without this the info panel starts scrolling internally on a
       320px-wide screen. */
    @media (max-width: 520px) {
      .steps, .hint, .subtitle, .endpoints { display: none; }
      .roster { max-height: clamp(54px, 14vh, 120px); }
    }
  </style>
</head>
<body>
  <div class="shell">
    <main class="card info">
      <h1 class="brand">
        <svg viewBox="0 0 64 64" aria-hidden="true">
          <defs>
            <mask id="kh-status-mark">
              <rect width="64" height="64" fill="white"/>
              <circle cx="32" cy="25" r="8" fill="black"/>
              <path d="M28.5 30.5 24 48h16l-4.5-17.5Z" fill="black"/>
            </mask>
          </defs>
          <rect x="4" y="4" width="56" height="56" rx="15" fill="currentColor" mask="url(#kh-status-mark)"/>
        </svg>
        Keyhole
      </h1>
      <p class="subtitle">Self-hosted sync for encrypted vaults.</p>
      <p class="badge">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="4" y="4" width="16" height="6" rx="2" />
          <rect x="4" y="14" width="16" height="6" rx="2" />
          <path d="M8 7h.01m-.01 10h.01M12 7h5m-5 10h5m-5-7v4" />
        </svg>
        Running · cannot read your vault
      </p>

      <div class="stats">
        <div class="stat"><span class="k">Status</span><span class="v ok">Healthy</span></div>
        <div class="stat"><span class="k">Accounts</span><span class="v">${accounts}</span></div>
        <div class="stat"><span class="k">Registration</span><span class="v ${registrationClass}" id="registration-value">${registration}</span></div>
        <div class="stat"><span class="k">Uptime</span><span class="v" id="uptime">—</span></div>
        <div class="stat"><span class="k">Failed auth</span><span class="v" id="failed-auth">0</span></div>
      </div>

      <div class="block">
        <p class="section-label">Server URL</p>
        <div class="url-row">
          <code id="server-url">${serverUrl}</code>
          <button type="button" id="copy-btn" title="Copy to clipboard">Copy</button>
        </div>
        <ol class="steps">
          <li>Settings → Sync server</li>
          <li>Account id and master password</li>
          <li>Register &amp; upload, then Sync now</li>
        </ol>
      </div>

      <div class="block endpoints">
        <p class="section-label">Endpoints</p>
        <div class="links">
          <a href="/api/v1/health">/health</a>
          <a href="/api/v1/console?format=json">/console</a>
        </div>
      </div>
${rosterSection}
${
  machineRows
    ? `
      <div class="block">
        <p class="section-label">This host</p>
        <div class="rows">${machineRows}
        </div>
      </div>`
    : ''
}
      <p class="hint">No vault UI here — open the Keyhole app or extension to unlock and sync.</p>
      <div class="spacer"></div>
${controlSection}
    </main>

    <section class="card console-card" aria-label="Live server console">
      <div class="console-header">
        <h2>Live console</h2>
        <span id="count">0</span>
        <select id="level-filter" aria-label="Filter by level">
          <option value="">All</option>
          <option value="info">Info</option>
          <option value="warn">Warn</option>
          <option value="error">Error</option>
        </select>
        <input type="search" id="text-filter" placeholder="Filter…" aria-label="Filter text" />
        <span id="live-state" class="live" data-state="offline">Connecting</span>
        <button type="button" id="pause-btn" aria-pressed="false">Pause</button>
        <button type="button" id="export-btn" title="Download the visible entries as JSON">Export</button>
        <button type="button" id="clear-btn">Clear</button>
      </div>
      <div id="console" role="log" aria-live="polite" aria-relevant="additions"></div>
    </section>
  </div>
  <script>
    /**
     * Save a Blob to disk. Declared at script scope, not inside either IIFE:
     * the console export and the backup download live in separate closures and
     * both need it.
     */
    function download(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      // Deferred: revoking synchronously after click cancels the download in
      // Firefox before it has read the blob.
      setTimeout(function () { URL.revokeObjectURL(url); }, 0);
    }

    (function () {
      const consoleEl = document.getElementById("console");
      const liveEl = document.getElementById("live-state");
      const pauseBtn = document.getElementById("pause-btn");
      const clearBtn = document.getElementById("clear-btn");
      const levelFilter = document.getElementById("level-filter");
      const textFilter = document.getElementById("text-filter");
      const countEl = document.getElementById("count");
      const exportBtn = document.getElementById("export-btn");
      const failedAuthEl = document.getElementById("failed-auth");
      const seen = new Set();
      // Entries are kept, not just their DOM rows, so changing a filter can
      // re-show something that was previously filtered out.
      const entries = [];
      const MAX = 300;
      let paused = false;
      let stickToBottom = true;

      function setLive(state, label) {
        liveEl.dataset.state = state;
        liveEl.textContent = label;
      }

      function fmtTime(iso) {
        try {
          return new Date(iso).toLocaleTimeString(undefined, { hour12: false });
        } catch {
          return "--:--:--";
        }
      }

      function text(entry) {
        return (entry.message || entry.method + " " + entry.path) +
          (entry.ip && entry.ip !== "local" ? " · " + entry.ip : "");
      }

      function matches(entry) {
        if (levelFilter.value && (entry.level || "info") !== levelFilter.value) return false;
        const q = textFilter.value.trim().toLowerCase();
        if (!q) return true;
        return (text(entry) + " " + entry.statusCode).toLowerCase().includes(q);
      }

      function rowFor(entry) {
        const row = document.createElement("div");
        row.className = "log-line " + (entry.level || "info");
        row.innerHTML =
          '<span class="time"></span><span class="status"></span>' +
          '<span class="ms"></span><span class="msg"></span>';
        row.querySelector(".time").textContent = fmtTime(entry.at);
        row.querySelector(".status").textContent = entry.statusCode;
        row.querySelector(".ms").textContent = entry.ms != null ? entry.ms + "ms" : "";
        row.querySelector(".msg").textContent = text(entry);
        return row;
      }

      function updateCounts() {
        const visible = entries.filter(matches).length;
        countEl.textContent = visible === entries.length
          ? String(entries.length)
          : visible + "/" + entries.length;
        // Counted over the whole buffer rather than the filtered view: "is
        // something hammering this server" should not change its answer because
        // a text filter happens to be set. 401 is a rejected credential, 429 is
        // the rate limiter having already stepped in.
        failedAuthEl.textContent = String(
          entries.filter(function (e) {
            return e.statusCode === 401 || e.statusCode === 429;
          }).length,
        );
      }

      function render() {
        consoleEl.textContent = "";
        for (const entry of entries.filter(matches)) consoleEl.appendChild(rowFor(entry));
        updateCounts();
        if (stickToBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
      }

      function append(entry) {
        if (seen.has(entry.id)) return;
        seen.add(entry.id);
        if (paused) return;
        entries.push(entry);
        while (entries.length > MAX) entries.shift();

        if (!matches(entry)) {
          updateCounts();
          return;
        }
        // Append rather than re-render: the common case is one new line, and
        // rebuilding 300 rows per request would make the console the most
        // expensive thing on the page.
        consoleEl.appendChild(rowFor(entry));
        while (consoleEl.children.length > MAX) {
          const first = consoleEl.firstElementChild;
          if (first) consoleEl.removeChild(first);
        }
        updateCounts();
        if (stickToBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
      }

      consoleEl.addEventListener("scroll", function () {
        stickToBottom = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 40;
      });

      levelFilter.addEventListener("change", render);
      textFilter.addEventListener("input", render);

      pauseBtn.addEventListener("click", function () {
        paused = !paused;
        pauseBtn.textContent = paused ? "Resume" : "Pause";
        pauseBtn.setAttribute("aria-pressed", paused ? "true" : "false");
      });

      clearBtn.addEventListener("click", function () {
        entries.length = 0;
        seen.clear();
        render();
      });

      exportBtn.addEventListener("click", function () {
        // Exports what you are looking at, not the server's buffer. The page
        // keeps MAX=300 entries while ConsoleLog holds 200, so a page left open
        // exports a superset of what /api/v1/console would return — and it
        // honours the active filters, which that endpoint cannot.
        const payload = JSON.stringify(entries.filter(matches), null, 2);
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        download(new Blob([payload], { type: "application/json" }), "keyhole-console-" + stamp + ".json");
      });

      const copyBtn = document.getElementById("copy-btn");
      copyBtn.addEventListener("click", async function () {
        const url = document.getElementById("server-url").textContent.trim();
        try {
          await navigator.clipboard.writeText(url);
          copyBtn.textContent = "Copied";
        } catch {
          // Clipboard needs a secure context. Loopback qualifies, but a plain
          // http:// origin on a LAN does not — select the text instead so the
          // button still does something useful.
          const range = document.createRange();
          range.selectNodeContents(document.getElementById("server-url"));
          const sel = getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
          copyBtn.textContent = "Select + copy";
        }
        setTimeout(function () { copyBtn.textContent = "Copy"; }, 1600);
      });

      const uptimeEl = document.getElementById("uptime");
      let uptime = ${JSON.stringify(Math.max(0, Math.floor(uptimeSeconds ?? 0)))};
      function renderUptime() {
        const d = Math.floor(uptime / 86400);
        const h = Math.floor((uptime % 86400) / 3600);
        const m = Math.floor((uptime % 3600) / 60);
        const s = uptime % 60;
        uptimeEl.textContent = d > 0 ? d + "d " + h + "h" : h > 0 ? h + "h " + m + "m" : m > 0 ? m + "m " + s + "s" : s + "s";
      }
      renderUptime();
      // Ticked locally rather than polled: the number only has to look right,
      // and a request per second to show it would be absurd.
      setInterval(function () { uptime += 1; renderUptime(); }, 1000);

      function connect() {
        setLive("offline", "Connecting");
        const source = new EventSource("/api/v1/console");
        source.onopen = function () { setLive("online", "Live"); };
        source.onmessage = function (event) {
          try {
            append(JSON.parse(event.data));
          } catch {
            /* ignore malformed frames */
          }
        };
        source.onerror = function () {
          setLive("offline", "Reconnecting");
          source.close();
          setTimeout(connect, 1500);
        };
      }

      connect();
    })();
${controlScript}
  </script>
</body>
</html>`;
}
