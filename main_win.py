"""
main_win.py
===========
Collector and AI compliance module for Windows Server 2016 config security auditing.
Connects to remote Windows host via WinRM, runs secedit /export to dump policy,
and feeds it to `parse_password_policy` from `password_policy_parser.py` (or tools/secedit_parser.py).
Evaluates compliance against target policies using Gemini AI.

Requirements:
- WinRM must be enabled on the target (`winrm quickconfig`).
- Account used needs local administrator or equivalent rights to run secedit.
"""

import os
import sys
import time
import logging
import json
import winrm
from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
from password_policy_parser import parse_password_policy
from dotenv import load_dotenv

# Load environment before initializing clients
load_dotenv()

from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

# Set up logging structure
logger = logging.getLogger("sentinel.collector.win")

# Initialize Gemini Clients for API key-rotation fallbacks
_raw_keys = [
    os.environ.get("GEMINI-API-KEY"),
    os.environ.get("GEMINI-API-KEY2"),
    os.environ.get("GEMINI-API-KEY3"),
]
CLIENTS = [genai.Client(api_key=k) for k in _raw_keys if k]
if not CLIENTS:
    raise RuntimeError("No GEMINI API keys found in .env")

MODELS = ["gemini-2.5-flash", "gemini-2.0-flash"]


class CollectorConnectionError(Exception):
    """
    Custom exception raised when connection or operation on WinRM collector fails.
    """
    pass


def generate_with_retry(max_retries=3, **kwargs):
    """Rotate through API keys, then model fallbacks, on 503/429 errors."""
    for model in MODELS:
        for key_idx, api_client in enumerate(CLIENTS):
            for attempt in range(max_retries):
                try:
                    return api_client.models.generate_content(model=model, **kwargs)
                except (genai_errors.ServerError, genai_errors.ClientError) as e:
                    # Safely get status code
                    s_code = getattr(e, 'status_code', None) or getattr(e, 'code', None)
                    
                    # 503 = Service Unavailable, 429 = Rate Limit
                    is_transient = s_code in (503, 429)
                    if not is_transient:
                        raise
                    
                    if attempt < max_retries - 1:
                        wait = 2 ** attempt
                        reason = "unavailable" if s_code == 503 else "rate-limited"
                        print(f"[retry] Key {key_idx + 1}/{len(CLIENTS)}, model={model} {reason} (attempt {attempt + 1}/{max_retries}). Retrying in {wait}s...")
                        time.sleep(wait)
                    else:
                        print(f"[rotate] Key {key_idx + 1} exhausted ({s_code}) for {model}, trying next key...")
                        break  # move to next key
        print(f"[fallback] All keys exhausted for {model}, switching model...")
    raise RuntimeError("All API keys and models exhausted. Please try again later.")


def generate_compliance_report(profile_json: str, cis_rules: str) -> str:
    """Send the security profile + CIS rules to Gemini for compliance analysis."""
    prompt = f"""You are a security compliance auditor.

Below are the CIS Windows Server 2016 Benchmark rules for password and account lockout policy:

--- CIS RULES ---
{cis_rules}
--- END CIS RULES ---

Below is the security profile collected from the remote machine (JSON):

--- SECURITY PROFILE ---
{profile_json}
--- END SECURITY PROFILE ---

For each CIS rule listed above, determine whether the machine's configuration PASSES or FAILS.
Output a structured compliance report with:
- Rule ID and title
- Status: PASS / FAIL / UNKNOWN (if data is insufficient to determine)
- Evidence: the relevant value(s) from the profile that justify the verdict
- Recommendation: what to fix if the status is FAIL

If a required data field for a rule is null/None in the security profile, mark that rule's status as UNKNOWN and note the missing field in Evidence — do not infer or guess a verdict.

Be concise but precise. Group results by password and account lockout policy sections."""

    response = generate_with_retry(
        contents=prompt,
        config=genai_types.GenerateContentConfig(temperature=0.1),
    )
    return response.text


def collect_password_policy(
    host: str,
    username: str,
    password: str,
    transport: str = "ntlm",
    use_ssl: bool = False,
    port: int = None
) -> dict:
    """
    Connects to target Windows host via WinRM, exports secedit config,
    reads it back, parses the password policy, and performs cleanup.

    Args:
        host (str): IP or hostname of target.
        username (str): WinRM username.
        password (str): WinRM password.
        transport (str): Auth transport (basic, ntlm, kerberos). Default ntlm.
        use_ssl (bool): Connect using HTTPS if True. Default False.
        port (int): Port override. Defaults to 5986 for HTTPS/SSL, else 5985.

    Returns:
        dict: Auditing response dictionary containing metadata and parsed policy data.
    """
    if port is None:
        port = 5986 if use_ssl else 5985

    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"
    temp_file = r"C:\Windows\Temp\sentinel_secpol.cfg"

    logger.info(f"Connecting to WinRM host at {endpoint} using {transport} transport")

    try:
        session = winrm.Session(endpoint, auth=(username, password), transport=transport)
    except (WinRMTransportError, WinRMOperationTimeoutError) as e:
        msg = f"Failed to initialize WinRM session to {host}: {e}"
        raise CollectorConnectionError(msg) from e

    # Step 1: Export security policy
    logger.info("Executing secedit /export command on remote host")
    try:
        r = session.run_cmd("secedit", ["/export", "/cfg", temp_file, "/quiet"])
    except (WinRMTransportError, WinRMOperationTimeoutError) as e:
        msg = f"WinRM transport/timeout error for host {host} during export step: {e}"
        raise CollectorConnectionError(msg) from e

    if r.status_code != 0:
        stderr_decoded = r.std_err.decode("utf-8", errors="replace")
        msg = f"secedit export command failed with status {r.status_code}: {stderr_decoded}"
        raise RuntimeError(msg)

    # Step 2: Read the file back
    logger.info("Reading exported security policy remote file")
    try:
        r = session.run_cmd("type", [temp_file])
    except (WinRMTransportError, WinRMOperationTimeoutError) as e:
        msg = f"WinRM transport/timeout error for host {host} during read step: {e}"
        raise CollectorConnectionError(msg) from e

    if r.status_code != 0:
        stderr_decoded = r.std_err.decode("utf-8", errors="replace")
        msg = f"Failed to read exported config file with status {r.status_code}: {stderr_decoded}"
        raise RuntimeError(msg)

    # Decode stdout with UTF-8 first, fallback to CP1252 (ANSI)
    try:
        secedit_output = r.std_out.decode("utf-8")
    except UnicodeDecodeError:
        logger.info("UTF-8 decoding failed, falling back to CP1252")
        secedit_output = r.std_out.decode("cp1252", errors="replace")

    # Step 3: Cleanup (delete temp file) - non-fatal
    logger.info("Cleaning up temp config file on remote host")
    try:
        cleanup_r = session.run_cmd("del", [temp_file])
        if cleanup_r.status_code != 0:
            stderr_decoded = cleanup_r.std_err.decode("utf-8", errors="replace")
            logger.warning(
                f"Non-fatal cleanup failed on host {host} with status {cleanup_r.status_code}: {stderr_decoded}"
            )
    except (WinRMTransportError, WinRMOperationTimeoutError) as e:
        logger.warning(f"Non-fatal WinRM transport/timeout error for host {host} during cleanup: {e}")

    # Step 4: Parse the output
    logger.info("Parsing retrieved security policy output")
    parsed_data = parse_password_policy(secedit_output)

    # Determine collection status
    # count non-None values to establish success vs partial vs failed
    total_keys = len(parsed_data)
    non_none_keys = sum(1 for v in parsed_data.values() if v is not None)

    if non_none_keys == total_keys:
        status = "success"
    elif non_none_keys > 0:
        status = "partial"
    else:
        status = "failed"

    return {
        "status": status,
        "source": "secedit_export",
        "host": host,
        "data": parsed_data,
        "error": None
    }


def run_compliance_check(collection_result: dict, cis_rules_path: str = None) -> str:
    """
    Takes the dict returned by collect_password_policy(), loads the CIS rules
    from password_policy.md, and returns the Gemini-generated compliance report
    text. Mirrors main.py's Step 7 (CIS compliance audit) but as a reusable
    function rather than inline main() code, since main_win.py's collector is
    already structured as an importable function.
    """
    if cis_rules_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path1 = os.path.join(base_dir, "password-policy.md")
        path2 = os.path.join(base_dir, "password_policy.md")
        if os.path.isfile(path1):
            cis_rules_path = path1
        else:
            cis_rules_path = path2

    if not os.path.isfile(cis_rules_path):
        logger.warning(f"CIS rules file not found at: {cis_rules_path}")
        return None

    logger.info(f"Loaded CIS rules from {cis_rules_path}")
    cis_rules_text = open(cis_rules_path, encoding="utf-8").read()

    logger.info("Sending profile to Gemini for compliance analysis")
    report = generate_compliance_report(
        json.dumps(collection_result["data"], indent=2), cis_rules_text
    )
    return report


if __name__ == "__main__":
    import argparse
    import getpass

    logging.basicConfig(level=logging.INFO)

    cli = argparse.ArgumentParser(
        description="Collect and audit Windows Server password policy via WinRM."
    )
    cli.add_argument("host",             help="Target Windows hostname or IP address")
    cli.add_argument("username",         help="WinRM username")
    cli.add_argument("--password",       default=None,
                     help="WinRM password (prompted securely if omitted)")
    cli.add_argument("--transport",      default="ntlm",
                     choices=["ntlm", "kerberos", "basic"],
                     help="WinRM auth transport (default: ntlm)")
    cli.add_argument("--ssl",            action="store_true", default=False,
                     help="Use HTTPS/SSL (port 5986). Default is HTTP (port 5985).")
    cli.add_argument("--port",           type=int, default=None,
                     help="WinRM port override")
    cli.add_argument("--cis-rules",      default=None,
                     help="Path to CIS rules markdown file (default: password-policy.md)")
    args = cli.parse_args()

    password = args.password or getpass.getpass(f"WinRM password for {args.username}@{args.host}: ")

    try:
        result = collect_password_policy(
            host=args.host,
            username=args.username,
            password=password,
            transport=args.transport,
            use_ssl=args.ssl,
            port=args.port,
        )
        print("\nCollection Result:")
        print(json.dumps(result, indent=4))

        if result["status"] == "failed":
            print("\nCompliance Check: Skipped — no data was collected to check against.")
        else:
            report = run_compliance_check(result, cis_rules_path=args.cis_rules)
            if report:
                print("\n" + "=" * 70)
                print("  CIS BENCHMARK COMPLIANCE REPORT")
                print("=" * 70 + "\n")
                print(report)
    except Exception as exc:
        print(f"\nCollection Failed with Exception: {exc}")

