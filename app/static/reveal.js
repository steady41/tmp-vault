(function () {
  const id = window.location.pathname.split("/").filter(Boolean).pop() || "";
  const keyB64 = window.location.hash.replace(/^#/, "");
  const statusEl = document.getElementById("status");
  const secretBox = document.getElementById("secret-box");
  const contentEl = document.getElementById("content");

  async function run() {
    if (!id) {
      statusEl.textContent = "Invalid link: missing secret id.";
      return;
    }
    if (!keyB64) {
      statusEl.textContent = "Incomplete link: the decryption key fragment is missing.";
      return;
    }

    let response;
    try {
      response = await fetch("/api/v1/secret/" + encodeURIComponent(id), { cache: "no-store" });
    } catch (err) {
      statusEl.textContent = "Network error: " + err.message;
      return;
    }

    if (response.status === 404) {
      statusEl.textContent = "This secret does not exist or was already destroyed.";
      return;
    }
    if (!response.ok) {
      statusEl.textContent = "Request failed (" + response.status + ").";
      return;
    }

    const data = await response.json();
    let plaintext;
    try {
      plaintext = await decryptSecret(data.ciphertext, keyB64);
    } catch (err) {
      statusEl.textContent = "Could not decrypt: the key is wrong, incomplete, or the data was tampered with.";
      return;
    }

    contentEl.textContent = plaintext;
    secretBox.hidden = false;
    history.replaceState(null, "", window.location.pathname);
  }

  run();
})();
