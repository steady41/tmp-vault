(function () {
  const $ = (id) => document.getElementById(id);
  const statusEl = $("status");
  const resultBox = $("result");
  const linkInput = $("link");
  const copyBtn = $("copy");

  function showError(message) {
    statusEl.textContent = message;
    statusEl.hidden = false;
  }

  $("create").addEventListener("click", async function () {
    const secret = $("secret").value;
    if (!secret.trim()) {
      showError("Enter a secret first.");
      return;
    }
    statusEl.hidden = true;
    resultBox.hidden = true;

    let encrypted;
    try {
      encrypted = await encryptSecret(secret);
    } catch (err) {
      showError("Encryption failed: " + err.message);
      return;
    }

    const ttlSeconds = Number($("ttl").value);
    const maxViews = Number($("max_views").value) || 1;

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
      showError("Network error: " + err.message);
      return;
    }

    if (!response.ok) {
      let detail = "Request failed (" + response.status + ")";
      try {
        const data = await response.json();
        if (data && data.detail) detail = data.detail;
      } catch (_) {}
      showError(detail);
      return;
    }

    const data = await response.json();
    const url = new URL(data.path, window.location.origin);
    url.hash = encrypted.keyB64;
    linkInput.value = url.toString();
    $("secret").value = "";
    copyBtn.textContent = "Copy";
    resultBox.hidden = false;
  });

  copyBtn.addEventListener("click", function () {
    linkInput.select();
    linkInput.setSelectionRange(0, 999999);
    navigator.clipboard
      .writeText(linkInput.value)
      .then(() => {
        copyBtn.textContent = "Copied";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1500);
      })
      .catch(() => {});
  });
})();
