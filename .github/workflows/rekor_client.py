import json, subprocess, shlex, tempfile, os

REKOR_SERVER = os.getenv("REKOR_SERVER", "https://rekor.sigstore.dev")

def anchor_blob_and_sig(blob_bytes: bytes, sig_bytes: bytes, pubkey_path: str):
    """Thin wrapper around `rekor-cli` if present. Raises if command fails."""
    with tempfile.NamedTemporaryFile(delete=False) as f_blob,          tempfile.NamedTemporaryFile(delete=False) as f_sig:
        f_blob.write(blob_bytes); f_blob.flush()
        f_sig.write(sig_bytes); f_sig.flush()
        cmd = f"rekor-cli upload --rekor_server {shlex.quote(REKOR_SERVER)} --artifact {f_blob.name} --signature {f_sig.name} --public-key {shlex.quote(pubkey_path)}"
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
    # Parse UUID from URL tail if present
    uuid = out.strip().split("/")[-1]
    info = subprocess.check_output(
        f"rekor-cli get --rekor_server {shlex.quote(REKOR_SERVER)} --uuid={uuid} -o json",
        shell=True, text=True
    )
    data = json.loads(info)
    return {
        "ok": True,
        "uuid": data.get("UUID") or uuid,
        "logIndex": data.get("Index"),
        "integratedTime": data.get("IntegratedTime")
    }
