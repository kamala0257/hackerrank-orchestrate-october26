from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

csv.field_size_limit(50_000_000)
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"

RESOURCE_RE = re.compile(r"\b(?:account|search|support|export|analytics|cache|marketing|email_delivery|audit_record|backup|data_flow|attachment|telemetry|profile|tombstone)[_-][A-Za-z0-9_-]+\b", re.I)
DELETE_RE = re.compile(r"delete|delet|deletion|erase|erasure|remove|removal|close my account|exclus[aã]o|eliminaci[oó]n|suppression|삭제|削除|löschung", re.I)
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {"REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2, "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4, "DISABLE_DATA_FLOW": 5, "BLOCK_RESTORE": 6, "DELETE_RECORD": 7, "REDACT_RECORD": 8, "ANONYMIZE_RECORD": 9, "VERIFY_RECORD_ABSENT": 10, "VERIFY_RECORD_PRESENT": 11, "VERIFY_RECORD_REDACTED": 12, "VERIFY_RECORD_ANONYMIZED": 13, "VERIFY_DATA_FLOW_DISABLED": 14, "VERIFY_RESTORE_BLOCKED": 15}
SYSTEMS = {"account":"account_service", "search":"search_service", "support":"support_platform", "export":"export_service", "analytics":"analytics_platform", "cache":"cache_service", "marketing":"marketing_platform", "email_delivery":"email_delivery_service", "audit_record":"security_service", "backup":"backup_service", "data_flow":"integration_service", "attachment":"support_platform", "telemetry":"analytics_platform", "tombstone":"account_service"}


def read_csv(name):
    with (DATA / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def date(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def clean(value):
    return str(value or "").strip().casefold()


def is_deletion(text):
    value = text or ""
    if DELETE_RE.search(value):
        return True
    lowered = value.casefold()
    return "account" in lowered and any(word in lowered for word in ("disconnected", "closed", "gone", "still existed", "privacy page", "request failed"))


def identifiers(req, identities, history):
    row = next((x for x in identities if clean(x["email"]) == clean(req["email"])), None)
    ids = {clean(req["email"])}
    if row:
        user_id = row["user_id"]
        for key in ("user_id", "name", "email", "phone", "email_hash"):
            if row.get(key): ids.add(clean(row[key]))
        ids.update(clean(v) for v in history.get(user_id, set()) if v)
    return {x for x in ids if len(x) >= 3}, row


def resource_system(resource):
    return SYSTEMS.get(resource.casefold().split("_", 1)[0], "account_service")


def records_from_file(file_id, manifest, text):
    """Return record-sized evidence units, never a whole-file match."""
    units = []
    suffix = Path(manifest["file_path"]).suffix.casefold()
    if suffix == ".json":
        try:
            data = json.loads(text)
            def walk(value):
                if isinstance(value, dict):
                    if value.get("resource_id"):
                        units.append((str(value["resource_id"]), json.dumps(value, ensure_ascii=False), file_id))
                    else:
                        for child in value.values(): walk(child)
                elif isinstance(value, list):
                    for child in value: walk(child)
            walk(data)
        except (ValueError, TypeError):
            pass
    elif suffix in {".sql", ".log", ".txt"}:
        for line in text.splitlines():
            resources = RESOURCE_RE.findall(line)
            if resources:
                for resource in sorted(set(resources), key=str.casefold):
                    units.append((resource, line, file_id))
    if not units:
        # PDFs/images may still have a manifest-side textual extraction in some datasets;
        # retain only a line-sized match when it exists, never all resources in the file.
        for line in text.splitlines():
            for resource in sorted(set(RESOURCE_RE.findall(line)), key=str.casefold):
                units.append((resource, line, file_id))
    return units


def category(resource, snippet):
    r, s = resource.casefold(), snippet.casefold()
    if r.startswith("data_flow") or "connector" in s or "sync" in s:
        return "flow"
    if r.startswith("backup") or "restore" in s:
        return "backup"
    if r.startswith("audit_record"):
        return "retain"
    if r.startswith(("analytics_", "telemetry_")):
        # Null identifiers and explicit anonymization are already safe.
        safe = any(x in s for x in ('"user_id": null', '"email": null', '"phone": null', "anonymized", "anonymous"))
        return "anon_safe" if safe else "anon"
    if r.startswith(("support_", "attachment_", "email_delivery_", "tombstone_")):
        return "redact_safe" if any(x in s for x in ("redacted", '"email": null', "personal data removed")) else "redact"
    return "absent_safe" if any(x in s for x in ("absent", "not found", "deleted", "no row")) else "delete"


def make_step(phase, system, resource, operation, state, evidence):
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource, "operation": operation, "state": state, "evidence_id": evidence}


def audit(req, identities, history, evidence):
    ids, user = identifiers(req, identities, history)
    cutoff = date(req["audit_at"])
    units = []
    for file_id, (manifest, text) in evidence.items():
        if date(manifest["captured_at"]) <= cutoff:
            for resource, snippet, evid in records_from_file(file_id, manifest, text):
                if any(token and token in clean(snippet) for token in ids):
                    units.append((resource, snippet, evid))
    # Operational evidence is record-scoped because the resource itself must mention the user.
    for row in read_csv("system_activity.csv"):
        if date(row["event_time"]) <= cutoff and any(token in clean(row["details"]) for token in ids):
            units.append((row["resource_id"], row["details"], row["activity_id"]))
    unique = {}
    for resource, snippet, evid in units:
        unique.setdefault((clean(resource), evid), (resource, snippet, evid))

    findings, remediations, verifications = [], [], []
    for resource, snippet, evid in unique.values():
        system = resource_system(resource)
        kind = category(resource, snippet)
        if kind == "retain":
            verifications.append(make_step("VERIFICATION", system, resource, "VERIFY_RECORD_PRESENT", "PRESENT", evid))
        elif kind == "flow":
            findings.append(make_step("FINDING", system, resource, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evid))
            remediations.append(make_step("REMEDIATION", system, resource, "DISABLE_DATA_FLOW", "DISABLED", ""))
            verifications.append(make_step("VERIFICATION", system, resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
        elif kind == "backup":
            findings.append(make_step("FINDING", system, resource, "REPORT_RESTORE_RISK", "ACTIVE", evid))
            remediations.append(make_step("REMEDIATION", system, resource, "BLOCK_RESTORE", "BLOCKED", ""))
            verifications.append(make_step("VERIFICATION", system, resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
        elif kind == "anon_safe":
            verifications.append(make_step("VERIFICATION", system, resource, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evid))
        elif kind == "redact_safe":
            verifications.append(make_step("VERIFICATION", system, resource, "VERIFY_RECORD_REDACTED", "REDACTED", evid))
        else:
            operation = "REPORT_EXPOSED_PII" if kind == "anon" or kind == "redact" else "REPORT_REMAINING_RECORD"
            remedy = "ANONYMIZE_RECORD" if kind == "anon" else "REDACT_RECORD" if kind == "redact" else "DELETE_RECORD"
            state = "ANONYMIZED" if kind == "anon" else "REDACTED" if kind == "redact" else "ABSENT"
            verify = "VERIFY_RECORD_ANONYMIZED" if kind == "anon" else "VERIFY_RECORD_REDACTED" if kind == "redact" else "VERIFY_RECORD_ABSENT"
            findings.append(make_step("FINDING", system, resource, operation, "PRESENT", evid))
            remediations.append(make_step("REMEDIATION", system, resource, remedy, state, ""))
            verifications.append(make_step("VERIFICATION", system, resource, verify, state, ""))

    # A primary account verification is required for every deletion audit. Use the stable
    # identity even when the account row itself is absent from evidence.
    if user:
        account = "account_" + user["user_id"].split("_")[-1]
        if not any(x["resource_id"].casefold() == account.casefold() for x in findings + verifications):
            verifications.append(make_step("VERIFICATION", "account_service", account, "VERIFY_RECORD_ABSENT", "ABSENT", "" if findings else next(iter(evidence), "")))
        audit_ids = [x for x in verifications if x["operation"] == "VERIFY_RECORD_PRESENT"]
    all_steps = findings + remediations + verifications
    all_steps.sort(key=lambda x: (PHASE_ORDER[x["phase"]], OP_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    for i, item in enumerate(all_steps, 1): item["step_no"] = i
    return ("INCOMPLETE" if findings else "COMPLETE"), all_steps


def main():
    import sys
    request_file = "sample_deletion_requests.csv" if "--sample" in sys.argv else "deletion_requests.csv"
    output_path = ROOT / "sample_output.generated.csv" if "--sample" in sys.argv else OUT
    identities = read_csv("user_identities.csv")
    history = {}
    for row in read_csv("user_audit_log.csv"):
        history.setdefault(row["user_id"], set()).update((row["old_value"], row["new_value"]))
    evidence = {}
    for manifest in read_csv("evidence_files.csv"):
        path = DATA / manifest["file_path"]
        try: text = path.read_text(encoding="utf-8", errors="ignore") if path.suffix.casefold() not in {".png", ".jpg", ".jpeg", ".pdf"} else ""
        except OSError: text = ""
        evidence[manifest["file_id"]] = (manifest, text)
    rows = []
    for req in read_csv(request_file):
        if not is_deletion(req["request_text"]): rows.append((req["case_id"], "NOT_APPLICABLE", []))
        else:
            status, steps = audit(req, identities, history, evidence)
            rows.append((req["case_id"], status, steps))
    rows.sort(key=lambda x: x[0])
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for case, status, steps in rows:
            writer.writerow([case, status, json.dumps(steps, ensure_ascii=False, separators=(",", ":"))])

if __name__ == "__main__": main()
