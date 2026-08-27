(() => {
  const id = window.location.pathname.split("/").filter(Boolean).pop() || "";
  const keyB64 = window.location.hash.replace(/^#/, "");

  const els = {
    status: document.getElementById("status"),
    wrap: document.getElementById("secret-wrap"),
    box: document.getElementById("secret-box"),
    copy: document.getElementById("copy"),
    empty: document.getElementById("empty"),
  };

  function showEmpty(icon, title, hint) {
    els.status.textContent = title;
    els.empty.innerHTML = `<div style="font-size:2rem; margin-bottom:8px;">${icon}</div><strong>${title}</strong><p style="color:var(--muted); font-size:0.88rem; margin-top:6px;">${hint}</p>`;
    els.empty.classList.remove("hidden");
  }

  els.copy.addEventListener("click", async () => {
    const text = els.box.textContent || "";
    if (!text) return;
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
      else throw new Error("no clipboard");
      els.copy.textContent = "Copied ✓";
    } catch {
      const r = document.createRange();
      r.selectNodeContents(els.box);
      const sel = window.getSelection();
      sel.removeAllRanges(); sel.addRange(r);
      try { document.execCommand("copy"); els.copy.textContent = "Copied ✓"; } catch {}
      sel.removeAllRanges();
    }
    setTimeout(() => (els.copy.textContent = "Copy to clipboard"), 1800);
  });

  async function run() {
    if (!/^[0-9a-f]{32}$/.test(id)) {
      showEmpty("🔍", "Invalid link", "The secret ID is missing or malformed.");
      return;
    }
    if (!keyB64) {
      showEmpty("🔑", "Incomplete link", "The decryption key is missing from the URL fragment. The sender must share the full link including the part after <code>#</code>.");
      return;
    }

    let response;
    try {
      response = await fetch(`/api/v1/secret/${encodeURIComponent(id)}`, { cache: "no-store" });
    } catch (err) {
      showEmpty("📡", "Network error", err.message);
      return;
    }

    if (response.status === 404) {
      showEmpty("🔥", "Already destroyed", "This secret does not exist or was already read. Links are single-use by design.");
      history.replaceState(null, "", window.location.pathname);
      return;
    }
    if (!response.ok) {
      showEmpty("⚠️", `Request failed (${response.status})`, "Please try again later.");
      return;
    }

    const data = await response.json();
    let plaintext;
    try {
      plaintext = await decryptSecret(data.ciphertext, keyB64);
    } catch {
      showEmpty("🔒", "Decryption failed", "The key is wrong or the data was tampered with. Make sure you opened the full link including the <code>#</code> fragment.");
      history.replaceState(null, "", window.location.pathname);
      return;
    }

    // Success — render and immediately scrub the key from the URL + history.
    els.box.textContent = plaintext;
    els.wrap.classList.remove("hidden");
    els.status.textContent = "Secret revealed — it has been destroyed on the server.";
    els.status.style.color = "var(--success)";
    history.replaceState(null, "", window.location.pathname);

    // Best-effort: clear the key variable. JS cannot zero the fragment from memory
    // reliably, but we avoid keeping it in an accessible variable longer than needed.
    // The plaintext remains only in the DOM until the tab is closed.
  }

  run();
})();
