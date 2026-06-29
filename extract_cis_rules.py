import sys
import re
import json
import pypdf

def main():
    pdf_path = "/home/sebtixd/ai-agents/ai-config-review-agent/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.0.pdf"
    start_page = 974  # 1-indexed

    print(f"[*] Loading {pdf_path}…", file=sys.stderr)
    try:
        reader = pypdf.PdfReader(pdf_path)
    except Exception as e:
        print(f"[-] Failed to read PDF: {e}", file=sys.stderr)
        sys.exit(1)

    total_pages = len(reader.pages)
    print(f"[+] PDF loaded. Total pages: {total_pages}", file=sys.stderr)

    # Keywords to search for
    keywords = ["ftp", "telnet", "ssh", "sshd", "vsftpd"]
    pattern = re.compile(r'^\s*(\d+(?:\.\d+)+)\s+(.+)$')

    extracted_rules = []

    # Iterate from page index start_page - 1 to total_pages
    for page_idx in range(start_page - 1, total_pages):
        text = reader.pages[page_idx].extract_text()
        for line in text.split("\n"):
            line = line.strip()
            # Check if this line starts with a recommendation number (e.g. 5.1.1)
            match = pattern.match(line)
            if match:
                rule_id = match.group(1)
                rule_desc = match.group(2)
                
                # Check for keywords
                lower_line = line.lower()
                if any(kw in lower_line for kw in keywords):
                    # Clean up trailing checkboxes " " or "Yes No"
                    rule_desc = re.sub(r'[\u2610\u25a1\uf06f\u2611\u2612\s]*\b(Yes|No)\b.*$', '', rule_desc)
                    rule_desc = re.sub(r'[\u2610\u25a1\uf06f\u2611\u2612\s]+$', '', rule_desc)
                    rule_desc = rule_desc.strip()
                    
                    extracted_rules.append({
                        "page": page_idx + 1,
                        "id": rule_id,
                        "description": rule_desc
                    })

    # Deduplicate rules by rule_id (in case they span multiple pages or appear in multiple checklists)
    seen_ids = set()
    unique_rules = []
    for r in extracted_rules:
        if r["id"] not in seen_ids:
            seen_ids.add(r["id"])
            unique_rules.append(r)

    # Sort by rule ID parts
    def id_key(r):
        return [int(x) for x in r["id"].split(".") if x.isdigit()]

    unique_rules.sort(key=id_key)

    # Output to markdown file
    output_md = "cis_extracted_rules.md"
    print(f"[*] Writing extracted rules to {output_md}…", file=sys.stderr)
    
    with open(output_md, "w", encoding="utf-8") as f:
        f.write("# CIS Ubuntu 24.04 LTS Benchmark Rules\n\n")
        f.write("Extracted from page 974 onwards, focusing on FTP, Telnet, and SSH.\n\n")
        
        # FTP rules
        f.write("## FTP Server / Client Rules\n")
        ftp_rules = [r for r in unique_rules if "ftp" in r["description"].lower() or "vsftpd" in r["description"].lower()]
        if ftp_rules:
            for r in ftp_rules:
                f.write(f"- **{r['id']}** {r['description']} (Page {r['page']})\n")
        else:
            f.write("*None found.*\n")
        f.write("\n")

        # Telnet rules
        f.write("## Telnet Server / Client Rules\n")
        telnet_rules = [r for r in unique_rules if "telnet" in r["description"].lower()]
        if telnet_rules:
            for r in telnet_rules:
                f.write(f"- **{r['id']}** {r['description']} (Page {r['page']})\n")
        else:
            f.write("*None found.*\n")
        f.write("\n")

        # SSH Rules
        f.write("## SSH Rules\n")
        ssh_rules = [r for r in unique_rules if "ssh" in r["description"].lower() or "sshd" in r["description"].lower()]
        if ssh_rules:
            for r in ssh_rules:
                f.write(f"- **{r['id']}** {r['description']} (Page {r['page']})\n")
        else:
            f.write("*None found.*\n")
        f.write("\n")

    print("[+] Done!", file=sys.stderr)

if __name__ == "__main__":
    main()
