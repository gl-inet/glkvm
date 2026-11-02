/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * glkvm paste-hook: RDP-style clipboard paste into the remote host.
 *
 * While the remote-screen stream (#stream-box) has keyboard focus, pressing
 * Cmd+V (macOS clients) or Ctrl+V (others) types the local clipboard text on
 * the remote via POST /api/hid/print. The V keydown/keyup are swallowed so
 * glweb does not forward them as HID keys, but default is NOT prevented, so
 * the browser (or Electron's Edit>Paste role) fires a native `paste` event,
 * whose clipboardData is read (no clipboard permission needed). If Meta is
 * held at paste time, a Ctrl tap is sent first so the remote Windows does not
 * open Start on the following lone Win release.
 * The print is deferred until the chord modifier (forwarded to the remote by
 * glweb) is released, or after 1500 ms we release it on the remote ourselves.
 *
 * Bundle findings (glweb assets/index-66RSN9oU.js, offsets approximate):
 *  - Stream element: ~829980 `T.keyboardHandler=new ss(a.value)` (ss = keyboard
 *    class os); ~832473 a = streamBoxRef -> `de("div",{ref_key:"streamBoxRef",
 *    ref:a,id:"stream-box",...,tabindex:"-1"...})`. So target is div#stream-box.
 *  - Auth: ~407802 `const vl=new C({timeout:3e4,baseURL:Zt.baseURL},(e=>{const
 *    t=Zt.getToken();t&&(e.headers.token=t)})` -> header `token: <tok>`.
 *    ~4800-5800 Zt.getToken() = JSON.parse(localStorage["gl-kvm-token-keys"])
 *    [deviceKey]; deviceKey "glkvm" unless baseURL.split("/")[2] is set;
 *    baseURL = location.href.split(origin)[1].split("#")[0] ("/" -> "").
 *  - Keymap: ~369656 gs(e)= ms().storage[e]||Dn[e]; ~368475 ms is the
 *    "serverStorage" store filled from gl.getServerStorage() -> s.config;
 *    ~408847 getServerStorage = vl.get("/api/system/get_config"). Not in
 *    localStorage: server-side config, key "keymap", default Ha.EN_US="en-us"
 *    (~284744 Dn.keymap). Response envelope {ok,result} (~407802 interceptor).
 */
(function () {
  "use strict";
  try {
    if (window.__glkvmPasteHook) return;
    window.__glkvmPasteHook = { version: "1" };
  } catch (e) { return; }

  var uad = navigator.userAgentData;
  var IS_MAC = /^Mac/.test(navigator.platform || "") || !!(uad && uad.platform === "macOS");
  var MOD_CODES = IS_MAC ? ["MetaLeft", "MetaRight"] : ["ControlLeft", "ControlRight"];
  var heldMod = null, swallowV = false, busy = false, onModUp = null;

  function isEditable(el) {
    if (!el || el.nodeType !== 1) return false;
    var t = el.tagName;
    return t === "INPUT" || t === "TEXTAREA" || t === "SELECT" || !!el.isContentEditable;
  }
  function inStreamBox(el) {
    return !!(el && el.nodeType === 1 && el.closest && el.closest("#stream-box"));
  }
  function isStreamTarget(ev) {
    var t = ev.target;
    if (!t || t.nodeType !== 1 || isEditable(t)) return false;
    if (inStreamBox(t)) return true;
    // Some Chromium builds dispatch clipboard events at <body> when the
    // focused element is not editable; accept that when the stream box
    // actually holds focus.
    var a = document.activeElement;
    return (t === document.body || t === document.documentElement) && !isEditable(a) && inStreamBox(a);
  }

  // Mirrors glweb's Zt (baseURL/deviceKey/getToken).
  function baseURL() {
    var b = (location.href.split(location.origin)[1] || "").split("#")[0];
    if (b && !b.endsWith("/")) b += "/";
    return b === "/" ? "" : b;
  }
  function token() {
    try {
      var k = baseURL().split("/")[2] || "glkvm";
      return (JSON.parse(localStorage.getItem("gl-kvm-token-keys")) || {})[k] || null;
    } catch (e) { return null; }
  }
  function apiUrl(path, params) {
    var b = baseURL();
    var u = new URL(b ? b.replace(/\/+$/, "") + path : path, location.origin);
    Object.keys(params || {}).forEach(function (k) { u.searchParams.set(k, params[k]); });
    return u.toString();
  }
  function req(method, path, params, body) {
    var h = {}, t = token();
    if (t) h.token = t;
    if (body != null) h["Content-Type"] = "text/plain; charset=utf-8";
    return fetch(apiUrl(path, params), { method: method, headers: h, body: body, credentials: "same-origin" });
  }

  async function keymap() {
    try {
      var r = await req("GET", "/api/system/get_config");
      if (r.ok) {
        var j = await r.json();
        var km = j && j.result && j.result.config && j.result.config.keymap;
        if (typeof km === "string" && km) return km;
      }
    } catch (e) { /* fall through */ }
    return "en-us";
  }

  function toast(msg) {
    try {
      var d = document.createElement("div");
      d.textContent = msg;
      d.style.cssText = "position:fixed;left:50%;bottom:32px;transform:translateX(-50%);" +
        "z-index:2147483647;background:rgba(32,32,32,.92);color:#fff;padding:8px 14px;" +
        "border-radius:6px;font:13px/1.4 sans-serif;pointer-events:none;";
      (document.body || document.documentElement).appendChild(d);
      setTimeout(function () { try { d.remove(); } catch (e) {} }, 3000);
    } catch (e) {}
  }

  // Resolves true if the modifier was released by the user, false on timeout/blur.
  function waitModRelease(ms) {
    return new Promise(function (resolve) {
      var timer = setTimeout(function () { onModUp = null; resolve(false); }, ms);
      onModUp = function (released) { clearTimeout(timer); onModUp = null; resolve(released); };
    });
  }

  async function doPaste(text, mod) {
    busy = true;
    try {
      if (mod === "MetaLeft" || mod === "MetaRight") {
        await req("POST", "/api/hid/events/send_key", { key: "ControlLeft", state: "true" });
        await req("POST", "/api/hid/events/send_key", { key: "ControlLeft", state: "false" });
      }
      if (mod && heldMod && !(await waitModRelease(1500))) {
        // Release the mod and its swap_cmd_ctrl counterpart (bundle ~364536 SwapCmdCtrlMap).
        var swapped = { MetaLeft: "ControlLeft", MetaRight: "ControlRight",
          ControlLeft: "MetaLeft", ControlRight: "MetaRight" }[mod];
        await req("POST", "/api/hid/events/send_key", { key: mod, state: "false" });
        await req("POST", "/api/hid/events/send_key", { key: swapped, state: "false" });
      }
      var km = await keymap();
      var r = await req("POST", "/api/hid/print", { limit: 0, keymap: km }, text);
      if (!r.ok) {
        toast(r.status === 416 ? "Too many text for paste"
          : (r.status === 401 || r.status === 403) ? "Not authenticated"
          : "Paste failed (" + r.status + ")");
      }
    } catch (e) {
      toast("Paste failed (network)");
    } finally {
      busy = false;
      onModUp = null;
    }
  }

  function isChord(ev) {
    if (ev.code !== "KeyV" || ev.shiftKey || ev.altKey) return false;
    return IS_MAC ? (ev.metaKey && !ev.ctrlKey) : (ev.ctrlKey && !ev.metaKey);
  }

  window.addEventListener("keydown", function (ev) {
    try {
      if (MOD_CODES.indexOf(ev.code) >= 0) { heldMod = ev.code; return; }
      if (ev.code !== "KeyV") return;
      if (isChord(ev) && isStreamTarget(ev)) {
        ev.stopImmediatePropagation(); // no preventDefault: let `paste` fire
        swallowV = true;
      } else {
        swallowV = false;
      }
    } catch (e) {}
  }, true);

  window.addEventListener("keyup", function (ev) {
    try {
      if (/^(Meta|Control)(Left|Right)$/.test(ev.code)) {
        swallowV = false;
        if (ev.code === heldMod) {
          heldMod = null;
          if (onModUp) onModUp(true);
        }
        return;
      }
      if (ev.code === "KeyV" && swallowV && heldMod) {
        swallowV = false;
        ev.stopImmediatePropagation();
      }
    } catch (e) {}
  }, true);

  window.addEventListener("blur", function (ev) {
    if (ev.target !== window) return;
    heldMod = null; swallowV = false;
    if (onModUp) onModUp(false);
  });

  window.addEventListener("paste", function (ev) {
    try {
      if (!isStreamTarget(ev)) return;
      var text = ev.clipboardData ? ev.clipboardData.getData("text/plain") : "";
      if (!text) return;
      ev.preventDefault();
      ev.stopImmediatePropagation();
      if (busy) { toast("Paste in progress"); return; }
      doPaste(text, heldMod);
    } catch (e) {}
  }, true);
})();
