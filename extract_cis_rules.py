import sys
import re
import argparse
import pypdf


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract CIS Benchmark rules from a PDF by keyword."
    )
    parser.add_argument(
        "pdf_path",
        help="Path to the CIS Benchmark PDF file.",
    )
    parser.add_argument(
        "topics",
        help=(
            "Comma-separated list of topics/keywords to extract rules for. "
            "Example: 'ssh,ftp,telnet,apache,nginx'"
        ),
    )
    parser.add_argument(
        "--start-page",
        type=int,
        default=1,
        help="1-indexed page to start extraction from (default: 1).",
    )
    parser.add_argument(
        "--output",
        default="cis_extracted_rules.md",
        help="Output markdown file path (default: cis_extracted_rules.md).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    pdf_path = args.pdf_path
def is_noise_line(line: str) -> bool:
    line = line.strip()
    if not line:
        return True

    # Checkbox line pattern: contains ballot boxes/squares, Yes/No, or just symbol/separator sequences
    cleaned = re.sub(r'[\u2610\u25a1\uf06f\u2611\u2612\s\-\|]+', '', line)
    cleaned_lower = cleaned.lower()
    if not cleaned or cleaned_lower in ("yesno", "yes", "no"):
        return True

    # Page headers / footers / standard boilerplates
    lower = line.lower()
    if re.match(r'^page\s+\d+$', lower):
        return True
    if "appendix" in lower and "table" in lower:
        return True
    if "benchmark" in lower and "recommendation" in lower:
        return True
    if lower in ("correctly", "yes no", "internal only - general", "internal only"):
        return True

    return False


def main():
    args = parse_args()

    pdf_path = args.pdf_path
    keywords = [kw.strip().lower() for kw in args.topics.split(",") if kw.strip()]
    start_page = args.start_page
    output_md = args.output

    if not keywords:
        print("[-] No keywords provided. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {pdf_path}…", file=sys.stderr)
    try:
        reader = pypdf.PdfReader(pdf_path)
    except Exception as e:
        print(f"[-] Failed to read PDF: {e}", file=sys.stderr)
        sys.exit(1)

    total_pages = len(reader.pages)
    print(f"[+] PDF loaded. Total pages: {total_pages}", file=sys.stderr)
    print(f"[*] Extracting rules for topics: {', '.join(keywords)}", file=sys.stderr)
    print(f"[*] Starting from page {start_page}", file=sys.stderr)

    # Pattern to match recommendation lines like "5.1.1 Ensure ..."
    pattern = re.compile(r'^\s*(\d+(?:\.\d+)+)\s+(.+)$')

    raw_rules = []

    for page_idx in range(start_page - 1, total_pages):
        text = reader.pages[page_idx].extract_text()
        if not text:
            continue

        current_rule = None

        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue

            match = pattern.match(line)
            if match:
                if current_rule:
                    raw_rules.append(current_rule)
                current_rule = {
                    "page": page_idx + 1,
                    "id": match.group(1),
                    "desc_parts": [match.group(2)],
                }
            elif current_rule is not None:
                if is_noise_line(line):
                    raw_rules.append(current_rule)
                    current_rule = None
                else:
                    current_rule["desc_parts"].append(line)

        # Flush the last active rule on this page
        if current_rule:
            raw_rules.append(current_rule)

    # Clean description titles and format raw rules
    cleaned_rules = []
    for r in raw_rules:
        desc = " ".join(r["desc_parts"])
        # Clean checkboxes or "Yes No" at the end of the line
        desc = re.sub(r'[\u2610\u25a1\uf06f\u2611\u2612\s]*\b(Yes|No)\b.*$', '', desc)
        desc = re.sub(r'[\u2610\u25a1\uf06f\u2611\u2612\s]+$', '', desc)
        desc = desc.strip()
        cleaned_rules.append({
            "page": r["page"],
            "id": r["id"],
            "description": desc
        })

    # Context-aware keyword matching with parent-child inheritance
    active_prefixes = {}
    extracted_rules = []

    for r in cleaned_rules:
        rule_id = r["id"]
        desc_lower = (rule_id + " " + r["description"]).lower()

        # Find directly matching topics for this rule
        direct_topics = [kw for kw in keywords if kw in desc_lower]

        # Check if this rule is a child of any already matching parent section
        inherited_topics = []
        for prefix, topics in active_prefixes.items():
            if rule_id.startswith(prefix + "."):
                inherited_topics.extend(t for t in topics if t not in inherited_topics)

        # Combine direct and inherited topics
        matched_topics = list(dict.fromkeys(direct_topics + inherited_topics))

        if matched_topics:
            # Register this rule ID as active for its children
            active_prefixes[rule_id] = matched_topics
            extracted_rules.append({
                "page": r["page"],
                "id": rule_id,
                "description": r["description"],
                "matched_topics": matched_topics,
            })

    # Deduplicate by rule_id
    seen_ids = set()
    unique_rules = []
    for r in extracted_rules:
        if r["id"] not in seen_ids:
            seen_ids.add(r["id"])
            unique_rules.append(r)

    # Sort numerically by rule ID parts
    def id_key(r):
        return [int(x) for x in r["id"].split(".") if x.isdigit()]

    unique_rules.sort(key=id_key)


    # Write markdown output
    print(f"[*] Writing {len(unique_rules)} rule(s) to {output_md}…", file=sys.stderr)

    with open(output_md, "w", encoding="utf-8") as f:
        f.write("# CIS Benchmark Extracted Rules\n\n")
        f.write(
            f"Extracted from **{pdf_path}** (starting page {start_page}), "
            f"filtering on topics: `{', '.join(keywords)}`.\n\n"
        )

        # One section per keyword
        for kw in keywords:
            f.write(f"## {kw.upper()} Rules\n")
            topic_rules = [r for r in unique_rules if kw in r["matched_topics"]]
            if topic_rules:
                for r in topic_rules:
                    f.write(f"- **{r['id']}** {r['description']} (Page {r['page']})\n")
            else:
                f.write("*None found.*\n")
            f.write("\n")

    print("[+] Done!", file=sys.stderr)


if __name__ == "__main__":
    main()
