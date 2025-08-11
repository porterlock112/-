import os
import yaml
import logging
import hashlib
import subprocess
import time
import csv
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pdfplumber
from git import Repo


def load_config(path="config.yaml"):
    with open(path, "r") as fh:
        return yaml.safe_load(fh)


class IntakeHandler(FileSystemEventHandler):
    def __init__(self, config, repo):
        super().__init__()
        self.config = config
        self.repo = repo
        self.log_file = config.get("log_file", "Chain_of_Custody_Log.csv")
        # create log file if not exists
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "filename",
                    "sha256",
                    "commit_id",
                ])

    def on_created(self, event):
        if event.is_directory:
            return
        try:
            self.process(event.src_path)
        except Exception:
            logging.exception("Error processing %s", event.src_path)

    def process(self, path):
        logging.info("Processing %s", path)
        processed_dir = self.config.get("processed_dir", "processed")
        os.makedirs(processed_dir, exist_ok=True)

        base = os.path.basename(path)
        name, ext = os.path.splitext(base)
        out_pdf = os.path.join(processed_dir, f"{name}_ocr.pdf")
        sidecar_txt = os.path.join(processed_dir, f"{name}.txt")
        sidecar_json = os.path.join(processed_dir, f"{name}.json")

        # OCR and convert to PDF/A using ocrmypdf
        logging.info("Running OCRmyPDF")
        cmd = [
            "ocrmypdf",
            "--output-type",
            "pdfa",
            "--sidecar",
            sidecar_txt,
            "--image-dpi",
            "300",
            "--tesseract",
            self.config.get("tesseract_cmd", "tesseract"),
            path,
            out_pdf,
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logging.error("OCRmyPDF failed: %s", e.stderr.decode())
            return

        # Extract text and tables with pdfplumber
        logging.info("Extracting text and tables")
        text = []
        tables = []
        with pdfplumber.open(out_pdf) as pdf:
            for page in pdf.pages:
                if page.extract_text():
                    text.append(page.extract_text())
                for table in page.extract_tables():
                    tables.append(table)
        with open(sidecar_json, "w") as f:
            json.dump({"text": "\n".join(text), "tables": tables}, f, indent=2)

        # Calculate SHA256
        logging.info("Hashing file")
        sha256 = hashlib.sha256()
        with open(out_pdf, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()

        # Add files to git and commit
        self.repo.git.add([out_pdf, sidecar_txt, sidecar_json])
        commit = self.repo.index.commit(f"Process {base}")

        # Append to chain of custody log
        with open(self.log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.utcnow().isoformat(),
                path,
                digest,
                commit.hexsha,
            ])
        self.repo.git.add(self.log_file)
        self.repo.index.commit(f"Log {base}")
        logging.info("Finished processing %s", path)


def main():
    config = load_config()
    log_params = {
        "level": logging.INFO,
        "format": "%(asctime)s %(levelname)s %(message)s",
    }
    if config.get("app_log"):
        log_params["filename"] = config["app_log"]
    logging.basicConfig(**log_params)

    repo = Repo(os.getcwd())

    vault = config.get("vault_root", "incoming")
    processed = config.get("processed_dir", "processed")
    os.makedirs(vault, exist_ok=True)
    os.makedirs(processed, exist_ok=True)

    event_handler = IntakeHandler(config, repo)
    observer = Observer()
    observer.schedule(event_handler, path=vault, recursive=False)
    observer.start()
    logging.info("Watching %s", vault)

    poll_interval = config.get("poll_interval", 5)
    try:
        while True:
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
