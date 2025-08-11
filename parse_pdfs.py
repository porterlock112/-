import re
import pdfplumber
import pandas as pd
from pathlib import Path

# Directory containing PDF files
source_dir = Path("source_docs")
if not source_dir.exists():
    source_dir = Path('.')  # fall back to current directory

metadata_file = Path('TRUTHLOCK_Exhibit_Crosswalk.csv')
try:
    metadata = pd.read_csv(metadata_file)
except Exception:
    metadata = pd.DataFrame()

NAME_PATTERN = re.compile(r"\b[A-Z][a-z]+(?: [A-Z][a-z]+)+\b")
DATE_PATTERN_DIGIT = re.compile(r"\b\d{2}[-/ ]\d{2}[-/ ]\d{4}\b")
DATE_PATTERN_MONTH = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* ?\d{1,2}, ?\d{4}\b")

def extract_text(pdf_path: Path) -> str:
    """Extract text from a PDF using pdfplumber."""
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""
    except Exception as exc:  # skip files that are not valid PDFs
        print(f"Skipping {pdf_path}: {exc}")
    return text

def parse_info(text: str) -> dict:
    """Parse names and dates from raw text."""
    names = NAME_PATTERN.findall(text)
    dates = DATE_PATTERN_DIGIT.findall(text) + DATE_PATTERN_MONTH.findall(text)
    return {"names": names, "dates": dates}

results = []
for pdf_path in source_dir.glob("*.pdf"):
    text = extract_text(pdf_path)
    info = parse_info(text)
    results.append({"file": pdf_path.name, **info})

# Save parsed results alongside any available metadata
output_df = pd.DataFrame(results)
if not metadata.empty:
    output_df = output_df.merge(metadata, how='left', left_on='file', right_on=metadata.columns[0])
output_df.to_csv('parsed_results.csv', index=False)
print(output_df)
