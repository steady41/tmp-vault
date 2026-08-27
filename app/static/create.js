(() => {
  const $ = (id) => document.getElementById(id);

  const els = {
    secret: $("secret"),
    ttl: $("ttl"),
    maxViews: $("max_views"),
    create: $("create"),
    status: $("status"),
    result: $("result"),
    link: $("link"),
    copy: $("copy"),
    counter: $("counter"),
    metaTtl: $("meta-ttl"),
    metaViews: $("meta-views"),
  };

  const TTL_LABELS = { 3600: "1h", 86400: "24h", 259200: "3 days", 604800: "7 days" };

  function setStatus(html, kind = "error") {
    const icon = kind === "error"
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>'
      : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>';
    els.status.innerHTML = `${icon}<span>${html}</span>`;
    els.status.className = `alert alert-${kind}`;
    els.status.classList.remove("hidden");
  }

  function clearStatus() {
    els.status.classList.add("hidden");
    els.status.textContent = "";
  }

  function updateCounter() {
    const len = els.secret.value.length;
    const c = els.counter;
    c.textContent = `${len} / 8000`;
    c.classList.toggle("warn", len > 6000 && len <= 7500);
    c.classList.toggle("danger", len > 7500);
  }

  els.secret.addEventListener("input", updateCounter);
  updateCounter();

  els.create.addEventListener("click", async () => {
    const secret = els.secret.value;
    if (!secret.trim()) {
      setStatus("Enter a secret first.");
      els.secret.focus();
      return;
    }

    clearStatus();
    els.result.classList.add("hidden");
    els.create.disabled = true;
    els.create.classList.add("loading");
    els.create.querySelector(".btn-label").textContent = "Encrypting…";

    let encrypted;
    try {
      encrypted = await encryptSecret(secret);
    } catch (err) {
      setStatus(`Encryption failed: ${err.message}`);
      resetButton();
      return;
    }

    const ttlSeconds = Number(els.ttl.value);
    const maxViews = Math.max(1, Math.min(100, Number(els.maxViews.value) || 1));

    let response;
    try {
      response = await fetch("/api/v1/secret", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ciphertext: encrypted.ciphertext,
          ttl_seconds: ttlSeconds,
          max_views: maxViews,
        }),
      });
    } catch (err) {
      setStatus(`Network error: ${err.message}`);
      resetButton();
      return;
    }

    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try {
        const data = await response.json();
        if (data?.detail) detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
      } catch (_) {}
      setStatus(detail);
      resetButton();
      return;
    }

    const data = await response.json();
    const url = new URL(data.path, window.location.origin);
    url.hash = encrypted.keyB64;

    els.link.value = url.toString();
    els.metaTtl.textContent = TTL_LABELS[ttlSeconds] || `${ttlSeconds}s`;
    els.metaViews.textContent = `${maxViews} view${maxViews > 1 ? "s" : ""}`;
    els.secret.value = "";
    updateCounter();
    els.copy.textContent = "Copy";
    els.result.classList.remove("hidden");
    els.result.scrollIntoView({ behavior: "smooth", block: "nearest" });
    resetButton();
  });

  function resetButton() {
    els.create.disabled = false;
    els.create.classList.remove("loading");
    els.create.querySelector(".btn-label").textContent = "Create burn-after-reading link";
  }

  // Copy with modern clipboard + legacy fallback
  els.copy.addEventListener("click", async () => {
    const val = els.link.value;
    if (!val) return;
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(val);
      else throw new Error("no clipboard");
      els.copy.textContent = "Copied ✓";
    } catch {
      els.link.select();
      els.link.setSelectionRange(0, 999999);
      try { document.execCommand("copy"); els.copy.textContent = "Copied ✓"; } catch {}
    }
    setTimeout(() => (els.copy.textContent = "Copy"), 1800);
  });

  // Ctrl/Cmd+Enter to submit
  els.secret.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") els.create.click();
  });
})();
