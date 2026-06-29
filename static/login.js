// Keystone login: WebAuthn passkey register/authenticate over the browser API.
//
// The server (webauthn-rs) speaks base64url for every binary field, while the browser
// WebAuthn API speaks ArrayBuffer. These helpers translate at the boundary, leaving the
// JSON shape exactly as webauthn-rs' CreationChallengeResponse / RegisterPublicKeyCredential
// (and the authentication equivalents) expect.

function b64urlToBuf(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)__Host-csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function postJson(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).error_description || detail; } catch (_) {}
    throw new Error(detail);
  }
  // finish endpoints return 204 (no body); begin endpoints return JSON.
  if (resp.status === 204) return null;
  return resp.json();
}

function setStatus(id, msg, kind) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

// --- Registration (session-protected; user already logged in) ---------------
async function registerPasskey() {
  setStatus("reg-status", "Touch your authenticator…", "");
  try {
    const cc = await postJson("/webauthn/register/begin", {});
    const pk = cc.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    if (pk.excludeCredentials) {
      pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    const cred = await navigator.credentials.create({ publicKey: pk });
    const body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      extensions: cred.getClientExtensionResults(),
      response: {
        attestationObject: bufToB64url(cred.response.attestationObject),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      },
    };
    await postJson("/webauthn/register/finish", body);
    setStatus("reg-status", "Passkey registered.", "ok");
    setTimeout(() => window.location.reload(), 900);
  } catch (e) {
    setStatus("reg-status", "Registration failed: " + e.message, "err");
  }
}

// --- Authentication (passwordless login) ------------------------------------
async function authenticatePasskey(returnTo) {
  const username = (document.getElementById("wa-username") || {}).value || "";
  if (!username) { setStatus("wa-status", "Enter your username first.", "err"); return; }
  setStatus("wa-status", "Touch your authenticator…", "");
  try {
    const rc = await postJson("/webauthn/authenticate/begin", { username });
    const pk = rc.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    if (pk.allowCredentials) {
      pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    const cred = await navigator.credentials.get({ publicKey: pk });
    const body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      extensions: cred.getClientExtensionResults(),
      response: {
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
      },
    };
    await postJson("/webauthn/authenticate/finish", body);
    setStatus("wa-status", "Authenticated.", "ok");
    window.location = returnTo || "/account";
  } catch (e) {
    setStatus("wa-status", "Passkey login failed: " + e.message, "err");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const regBtn = document.getElementById("register-passkey");
  if (regBtn) regBtn.addEventListener("click", registerPasskey);
  const waBtn = document.getElementById("passkey-login");
  if (waBtn) {
    waBtn.addEventListener("click", () => authenticatePasskey(waBtn.dataset.returnTo));
  }
});
