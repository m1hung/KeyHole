/**
 * Browser landing page for the sync server.
 *
 * Mirrors the web app's unlock-screen card: same tokens, type, radii, and the
 * brand mark / local-server icons so opening :8787 feels like Keyhole rather
 * than a bare Fastify 404. Includes a live SSE console of recent API activity.
 */

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
  control?: { token: string; port: number } | undefined;
}

/** The origin comes from a request header, so it is attacker-controlled text. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function renderStatusPage({
  port,
  accounts,
  allowRegistration,
  origin,
  control,
}: StatusPageProps): string {
  const registration = allowRegistration ? 'Open' : 'Closed';
  const registrationClass = allowRegistration ? 'ok' : 'warn';
  const serverUrl = escapeHtml(origin ?? `http://127.0.0.1:${port}`);

  // Both halves are empty unless the caller decided this viewer is local. No
  // markup, no token, no script — a remote page has nothing to drive and
  // nothing to steal, rather than disabled buttons hinting at an endpoint.
  const controlSection = control
    ? `
        <p class="section-label">Server controls</p>
        <div class="controls">
          <button type="button" id="restart-btn">Restart server</button>
          <button type="button" id="stop-btn" class="danger">Stop server</button>
        </div>
        <p id="control-msg">Local session — these act on this machine.</p>`
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
      --radius: 12px;
      --shadow-contact: light-dark(0 1px 2px rgb(15 23 42 / 8%), 0 1px 2px rgb(0 0 0 / 50%));
      --shadow-ambient: light-dark(0 8px 24px -6px rgb(15 23 42 / 12%), 0 8px 24px -6px rgb(0 0 0 / 45%));
      --shadow: var(--shadow-contact), var(--shadow-ambient);
      --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      --dur-slow: 300ms;
      --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
      color-scheme: light dark;
    }

    * { box-sizing: border-box; }

    html, body {
      height: 100%;
      margin: 0;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }

    .center-screen {
      display: flex;
      align-items: flex-start;
      justify-content: center;
      min-height: 100%;
      padding: 24px;
    }

    .layout {
      width: 100%;
      max-width: 720px;
      display: grid;
      gap: 16px;
      animation: card-in var(--dur-slow) var(--ease-out) both;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 28px;
      width: 100%;
    }

    @keyframes card-in {
      from { opacity: 0; transform: translateY(10px) scale(0.985); }
      to   { opacity: 1; transform: none; }
    }

    @media (prefers-reduced-motion: reduce) {
      .layout { animation-duration: 1ms; }
    }

    h1 {
      display: flex;
      align-items: center;
      gap: 9px;
      font-size: 22px;
      margin: 0 0 4px;
      letter-spacing: -0.01em;
    }

    h1 svg {
      color: var(--accent);
      flex: none;
    }

    .subtitle {
      color: var(--text-dim);
      margin: 0 0 12px;
      font-size: 13px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin: 0 0 20px;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 12px;
      font-weight: 500;
    }

    .badge svg { flex: none; }

    .facts {
      list-style: none;
      margin: 0 0 20px;
      padding: 0;
      display: grid;
      gap: 10px;
    }

    .facts li {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 12px;
      border-radius: 10px;
      background: var(--surface-2);
      border: 1px solid var(--border);
    }

    .facts .label {
      color: var(--text-dim);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .facts .value {
      font-weight: 600;
      text-align: right;
    }

    .facts a {
      color: var(--accent);
      text-decoration: none;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 500;
    }

    .facts a:hover { text-decoration: underline; }

    .ok { color: var(--ok); }
    .warn { color: var(--warn); }

    .section-label {
      margin: 0 0 8px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-dim);
    }

    pre.connect {
      margin: 0;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      overflow: auto;
      white-space: pre-wrap;
    }

    .hint {
      margin: 16px 0 0;
      color: var(--text-dim);
      font-size: 12px;
    }

    .console-card {
      padding: 0;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      min-height: 280px;
      max-height: min(52vh, 420px);
    }

    .console-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }

    .console-header h2 {
      margin: 0;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: var(--text-dim);
    }

    .console-meta {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 12px;
      color: var(--text-dim);
    }

    .console-meta .live {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--ok);
      font-weight: 600;
    }

    .console-meta .live[data-state="offline"] {
      color: var(--danger);
    }

    .console-meta .live::before {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 0 3px color-mix(in srgb, currentColor 22%, transparent);
    }

    .console-meta button {
      font: inherit;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--text);
      padding: 4px 10px;
    }

    .console-meta button:hover {
      border-color: var(--accent);
      color: var(--accent);
    }

    .controls {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }

    .controls button {
      font: inherit;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--text);
      padding: 6px 14px;
    }

    .controls button:hover:not(:disabled) {
      border-color: var(--accent);
      color: var(--accent);
    }

    /* Stopping ends vault sync for every device, so it should not look like
       the same weight of action as restarting. */
    .controls button.danger:hover:not(:disabled) {
      border-color: var(--danger);
      color: var(--danger);
    }

    .controls button:disabled {
      opacity: 0.55;
      cursor: default;
    }

    #control-msg {
      font-size: 12px;
      color: var(--text-dim);
      min-height: 1.2em;
    }

    #control-msg.err { color: var(--danger); }

    #console {
      flex: 1;
      margin: 0;
      padding: 10px 12px 14px;
      overflow: auto;
      overscroll-behavior: contain;
      background: light-dark(#0f1419, #0a0e14);
      color: light-dark(#d5dde6, #c8d1dc);
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      border: none;
      border-radius: 0;
      white-space: pre;
    }

    #console:empty::before {
      content: "Waiting for activity…";
      color: var(--text-dim);
    }

    .log-line {
      display: grid;
      grid-template-columns: 76px 52px 44px 1fr;
      gap: 10px;
      padding: 2px 0;
      border-bottom: 1px solid rgb(255 255 255 / 4%);
    }

    .log-line .time { color: #7f8b99; }
    .log-line .status { font-weight: 600; }
    .log-line .ms { color: #7f8b99; text-align: right; }
    .log-line .msg { color: inherit; overflow: hidden; text-overflow: ellipsis; }

    .log-line.info .status { color: #5b9fd4; }
    .log-line.warn .status { color: #d29922; }
    .log-line.error .status { color: #ff7b72; }
  </style>
</head>
<body>
  <div class="center-screen">
    <div class="layout">
      <main class="card">
        <h1>
          <svg width="26" height="26" viewBox="0 0 64 64" aria-hidden="true">
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
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <rect x="4" y="4" width="16" height="6" rx="2" />
            <rect x="4" y="14" width="16" height="6" rx="2" />
            <path d="M8 7h.01m-.01 10h.01M12 7h5m-5 10h5m-5-7v4" />
          </svg>
          Running · cannot read your vault
        </p>

        <ul class="facts">
          <li>
            <span class="label">Status</span>
            <span class="value ok">Healthy</span>
          </li>
          <li>
            <span class="label">Accounts</span>
            <span class="value">${accounts}</span>
          </li>
          <li>
            <span class="label">Registration</span>
            <span class="value ${registrationClass}">${registration}</span>
          </li>
          <li>
            <span class="label">Health</span>
            <a href="/api/v1/health">/api/v1/health</a>
          </li>
        </ul>

        <p class="section-label">Connect from the app</p>
        <pre class="connect">Server URL   ${serverUrl}
Settings  →  Sync server
1. Pick an account id
2. Enter master password
3. Register &amp; upload  (first device)
4. Sync now             (after that)</pre>

        <p class="hint">There is no vault UI on this host — open the Keyhole web app or extension to unlock and sync.</p>
${controlSection}
      </main>

      <section class="card console-card" aria-label="Live server console">
        <div class="console-header">
          <h2>Live console</h2>
          <div class="console-meta">
            <span id="live-state" class="live" data-state="offline">Connecting</span>
            <button type="button" id="pause-btn" aria-pressed="false">Pause</button>
            <button type="button" id="clear-btn">Clear</button>
          </div>
        </div>
        <div id="console" role="log" aria-live="polite" aria-relevant="additions"></div>
      </section>
    </div>
  </div>
  <script>
    (function () {
      const consoleEl = document.getElementById("console");
      const liveEl = document.getElementById("live-state");
      const pauseBtn = document.getElementById("pause-btn");
      const clearBtn = document.getElementById("clear-btn");
      const seen = new Set();
      let paused = false;
      let stickToBottom = true;

      function setLive(state, label) {
        liveEl.dataset.state = state;
        liveEl.textContent = label;
      }

      function fmtTime(iso) {
        try {
          const d = new Date(iso);
          return d.toLocaleTimeString(undefined, { hour12: false });
        } catch {
          return "--:--:--";
        }
      }

      function append(entry) {
        if (seen.has(entry.id)) return;
        seen.add(entry.id);
        if (paused) return;

        const row = document.createElement("div");
        row.className = "log-line " + (entry.level || "info");
        row.innerHTML =
          '<span class="time">' + fmtTime(entry.at) + "</span>" +
          '<span class="status">' + entry.statusCode + "</span>" +
          '<span class="ms">' + (entry.ms != null ? entry.ms + "ms" : "") + "</span>" +
          '<span class="msg"></span>';
        row.querySelector(".msg").textContent =
          (entry.message || entry.method + " " + entry.path) +
          (entry.ip && entry.ip !== "local" ? " · " + entry.ip : "");
        consoleEl.appendChild(row);

        while (consoleEl.children.length > 300) {
          const first = consoleEl.firstElementChild;
          if (first) consoleEl.removeChild(first);
        }

        if (stickToBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
      }

      consoleEl.addEventListener("scroll", function () {
        const distance = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight;
        stickToBottom = distance < 40;
      });

      pauseBtn.addEventListener("click", function () {
        paused = !paused;
        pauseBtn.textContent = paused ? "Resume" : "Pause";
        pauseBtn.setAttribute("aria-pressed", paused ? "true" : "false");
      });

      clearBtn.addEventListener("click", function () {
        consoleEl.textContent = "";
        seen.clear();
      });

      function connect() {
        setLive("offline", "Connecting");
        const source = new EventSource("/api/v1/console");
        source.onopen = function () {
          setLive("online", "Live");
        };
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
