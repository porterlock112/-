import re
import pdfplumber
import pandas as pd
from pathlib import Path
from zipfile import ZipFile

NAME_PATTERN = re.compile(r"\b[A-Z][a-z]+(?: [A-Z][a-z]+)+\b")
DATE_PATTERN_DIGIT = re.compile(r"\b\d{2}[-/ ]\d{2}[-/ ]\d{4}\b")
DATE_PATTERN_MONTH = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* ?\d{1,2}, ?\d{4}\b")


def extract_text(pdf_path: Path) -> str:
    text = ""
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text() or ""
    return text


def parse_info(text: str) -> dict:
    names = NAME_PATTERN.findall(text)
    dates = DATE_PATTERN_DIGIT.findall(text) + DATE_PATTERN_MONTH.findall(text)
    return {"names": names, "dates": dates}


def parse_pdfs_in_dir(directory: Path) -> pd.DataFrame:
    results = []
    for pdf_path in directory.glob("*.pdf"):
        try:
            text = extract_text(pdf_path)
            info = parse_info(text)
            results.append({"file": pdf_path.name, **info})
        except Exception as exc:
            print(f"Skipping {pdf_path}: {exc}")
    return pd.DataFrame(results)


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def parse_zip(zip_path: Path, out_dir: Path) -> pd.DataFrame:
    ensure_dir(out_dir)
    with ZipFile(zip_path, 'r') as z:
        z.extractall(out_dir)
    return parse_pdfs_in_dir(out_dir)


def summarize_texts(dir_path: Path, out_file: Path):
    with open(out_file, 'w') as fh:
        for pdf in sorted(dir_path.glob("*.pdf")):
            fh.write(f"# {pdf.name}\n")
            try:
                fh.write(extract_text(pdf).strip() + "\n")
            except Exception as exc:
                fh.write(f"[Error reading {pdf.name}: {exc}]\n")


def main():
    # Parse root PDFs
    root_df = parse_pdfs_in_dir(Path('.'))
    root_df.to_csv('parsed_results.csv', index=False)

    # Parse motions zip
    motions_zip = Path('Truthlock_Motions_Full_Export.zip')
    if motions_zip.exists():
        df = parse_zip(motions_zip, Path('decoded_zip'))
        df.to_csv('parsed_results_decoded_zip.csv', index=False)

    # Extract superbrief placeholder text
    sb_zip = Path('TRUTHLOCK_SUPERBRIEF_X5_BUNDLE.zip')
    if sb_zip.exists():
        out_dir = Path('decoded_superbrief')
        ensure_dir(out_dir)
        with ZipFile(sb_zip, 'r') as z:
            z.extractall(out_dir)
        summarize_texts(out_dir, Path('superbrief_text.txt'))


if __name__ == '__main__':
    main()
