#!/usr/bin/env python3
"""
Meraki Organization Cleanup - Safe Wrapper

Purpose:
- Audit Meraki organizations before considering deletion.
- DRY RUN / audit is the default.
- Deletion is available only with --apply and multiple safety gates.
- No devices, admins, licenses, SAML settings, or networks are modified by this script.
- Standard library only; no Meraki SDK required.
- Uses the X-Cisco-Meraki-API-Key header, matching the validated working request.
- Distinguishes active licensing from expired-only licensing.
- Classifies each organization into a clear cleanup category.

Public recording mode:
    --public-display

Audit every organization:
    --audit-all

Delete one organization only after it passes the audit:
    --apply

WARNING:
Deleting a Meraki organization is non-reversible.
"""

import argparse
import csv
import getpass
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_URL = "https://api.meraki.com/api/v1"
USER_AGENT = "JoeDiCerboTech-Meraki-Organization-Cleanup/7.0"


class MerakiAPI:
    def __init__(self, api_key):
        self.api_key = api_key

    def request(self, method, path_or_url, body=None, allow_error=False):
        url = path_or_url if path_or_url.startswith("http") else BASE_URL + path_or_url
        data = None
        headers = {
            "X-Cisco-Meraki-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        for attempt in range(5):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=45) as response:
                    raw = response.read()
                    parsed = None
                    if raw:
                        try:
                            parsed = json.loads(raw.decode("utf-8"))
                        except Exception:
                            parsed = raw.decode("utf-8", errors="replace")
                    return {
                        "ok": True,
                        "status": response.status,
                        "data": parsed,
                        "headers": dict(response.headers.items()),
                    }

            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", errors="replace")
                if e.code == 429 and attempt < 4:
                    retry = e.headers.get("Retry-After", "2")
                    try:
                        wait = max(float(retry), 1.0)
                    except ValueError:
                        wait = 2.0
                    time.sleep(wait)
                    continue

                result = {
                    "ok": False,
                    "status": e.code,
                    "error": raw,
                    "headers": dict(e.headers.items()),
                }
                if allow_error:
                    return result
                raise RuntimeError(
                    f"Meraki API {method} {urllib.parse.urlsplit(url).path} "
                    f"failed with HTTP {e.code}: {raw}"
                )

            except urllib.error.URLError as e:
                result = {"ok": False, "status": None, "error": str(e), "headers": {}}
                if allow_error:
                    return result
                raise RuntimeError(f"Meraki API connection failed: {e}")

        raise RuntimeError("Meraki API retry limit reached.")

    def get(self, path, allow_error=False):
        return self.request("GET", path, allow_error=allow_error)

    def delete(self, path, allow_error=False):
        return self.request("DELETE", path, allow_error=allow_error)

    def get_all(self, path, allow_error=False):
        """Follow Meraki Link rel=next pagination when present."""
        items = []
        url = BASE_URL + path
        while url:
            result = self.request("GET", url, allow_error=allow_error)
            if not result["ok"]:
                return result

            data = result.get("data")
            if isinstance(data, list):
                items.extend(data)
            elif data is not None:
                return {
                    "ok": False,
                    "status": None,
                    "error": "Expected a list from paginated endpoint.",
                    "headers": {},
                }

            url = parse_next_link(result.get("headers", {}).get("Link"))

        return {"ok": True, "status": 200, "data": items, "headers": {}}


def parse_next_link(link_header):
    if not link_header:
        return None
    for part in link_header.split(","):
        if 'rel="next"' in part:
            m = re.search(r"<([^>]+)>", part)
            if m:
                return m.group(1)
    return None


def safe_error(result):
    status = result.get("status")
    error = (result.get("error") or "").strip()
    if error:
        compact = " ".join(error.split())
        if len(compact) > 300:
            compact = compact[:297] + "..."
        return f"HTTP {status}: {compact}" if status else compact
    return f"HTTP {status}" if status else "unavailable"


def count_list(result):
    if result.get("ok") and isinstance(result.get("data"), list):
        return len(result["data"])
    return None


def bool_text(value):
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "UNKNOWN"


def assess_license_state(overview):
    """
    Return a normalized view of licensing.

    Cisco's license overview mixes licensing models:
    - Co-term: status / expirationDate / licensedDeviceCounts
    - Per-device: states.*
    - Systems Manager: systemsManager.counts

    Important V2 behavior:
    licensedDeviceCounts is NOT treated as active/valuable licensing when the
    co-term status explicitly says the organization is expired. That field can
    describe historical licensed device counts even after expiration.
    """
    if not overview.get("ok") or not isinstance(overview.get("data"), dict):
        return {
            "known": False,
            "activeValueCount": None,
            "expiredOnly": False,
            "notes": "License overview could not be read.",
        }

    d = overview["data"]
    active_value = 0
    expired_only = False
    notes = []

    status = str(d.get("status") or "").strip()
    expiration = d.get("expirationDate")
    status_lower = status.lower()
    coterm_expired = "expired" in status_lower and "expires soon" not in status_lower

    ldc = d.get("licensedDeviceCounts") or {}
    ldc_total = 0
    if isinstance(ldc, dict):
        ldc_total = sum(v for v in ldc.values() if isinstance(v, int) and v > 0)

    # Co-termination licensing: only count licensedDeviceCounts as active value
    # when Meraki does NOT explicitly report the org as expired.
    if ldc_total:
        if coterm_expired:
            expired_only = True
            notes.append(f"expired co-term licensedDeviceCounts={ldc_total}")
        else:
            active_value += ldc_total
            notes.append(f"licensedDeviceCounts={ldc_total}")

    # Per-device licensing states.
    states = d.get("states") or {}
    if isinstance(states, dict):
        expired_count = ((states.get("expired") or {}).get("count"))
        if isinstance(expired_count, int) and expired_count > 0:
            notes.append(f"expired={expired_count}")

        # These all represent current or still-valuable license inventory.
        for key in ("active", "expiring", "recentlyQueued", "unused", "unusedActive"):
            entry = states.get(key) or {}
            count = entry.get("count")
            if isinstance(count, int) and count > 0:
                active_value += count
                notes.append(f"{key}={count}")

    # Per-device unassigned license types can also represent usable value.
    license_types = d.get("licenseTypes") or []
    if isinstance(license_types, list):
        unassigned = 0
        for item in license_types:
            if not isinstance(item, dict):
                continue
            count = ((item.get("counts") or {}).get("unassigned"))
            if isinstance(count, int) and count > 0:
                unassigned += count
        if unassigned:
            active_value += unassigned
            notes.append(f"unassigned={unassigned}")

    sm = ((d.get("systemsManager") or {}).get("counts") or {})
    if isinstance(sm, dict):
        for key in ("activeSeats", "unassignedSeats"):
            count = sm.get(key)
            if isinstance(count, int) and count > 0:
                active_value += count
                notes.append(f"SM {key}={count}")

    if status:
        notes.append(f"status={status}")
    if expiration:
        notes.append(f"expiration={expiration}")

    # "Expired only" means we saw expired licensing information but no current value.
    if active_value == 0 and (coterm_expired or expired_only):
        expired_only = True

    return {
        "known": True,
        "activeValueCount": active_value,
        "expiredOnly": expired_only,
        "notes": "; ".join(notes) if notes else "No active license evidence returned.",
    }


def classify_org(audit):
    """Return a concise cleanup classification for the audit result."""
    # If core prerequisites cannot be verified, never imply the org is safe.
    if (
        audit["inventoryDeviceCount"] is None
        or audit["adminCount"] is None
        or audit["samlEnabled"] is None
        or audit["networkCount"] is None
        or audit.get("configTemplateCount") is None
    ):
        return "API ACCESS BLOCKED"

    # Device inventory or current license value means this is not a cleanup candidate.
    if (
        (audit["inventoryDeviceCount"] or 0) > 0
        or (
            audit["licenseActiveValueCount"] is not None
            and audit["licenseActiveValueCount"] > 0
        )
    ):
        return "ACTIVE - DO NOT DELETE"

    # Extra admins are still the first cleanup step.
    if audit["adminCount"] != 1 or audit["fullAdminCount"] != 1:
        return "SAFE AFTER ADMIN CLEANUP"

    # Meraki requires SAML disabled, zero networks, and zero config templates.
    if (
        audit["samlEnabled"]
        or (audit["networkCount"] or 0) > 0
        or (audit.get("configTemplateCount") or 0) > 0
    ):
        return "CONFIG CLEANUP REQUIRED"

    return "READY FOR DELETE REVIEW"


def audit_org(api, org):
    org_id = str(org["id"])

    networks = api.get_all(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/networks?perPage=1000",
        allow_error=True,
    )
    inventory = api.get_all(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/inventory/devices?perPage=1000",
        allow_error=True,
    )
    admins = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/admins",
        allow_error=True,
    )
    saml = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/saml",
        allow_error=True,
    )
    licenses = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/licenses/overview",
        allow_error=True,
    )
    config_templates = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/configTemplates",
        allow_error=True,
    )

    network_count = count_list(networks)
    inventory_count = count_list(inventory)
    admin_count = count_list(admins)
    config_template_count = count_list(config_templates)

    full_admins = None
    if admins.get("ok") and isinstance(admins.get("data"), list):
        full_admins = sum(1 for a in admins["data"] if a.get("orgAccess") == "full")

    saml_enabled = None
    if saml.get("ok") and isinstance(saml.get("data"), dict):
        saml_enabled = bool(saml["data"].get("enabled"))

    license_state = assess_license_state(licenses)
    license_count = license_state["activeValueCount"]
    license_notes = license_state["notes"]

    blockers = []
    reviews = []

    # Meraki's documented prerequisites.
    if inventory_count is None:
        blockers.append(f"Inventory could not be verified ({safe_error(inventory)}).")
    elif inventory_count > 0:
        blockers.append(f"{inventory_count} device(s) remain in organization inventory.")

    if admin_count is None:
        blockers.append(f"Administrators could not be verified ({safe_error(admins)}).")
    elif admin_count != 1:
        blockers.append(
            f"{admin_count} dashboard administrator(s) exist; Meraki requires only one."
        )

    if full_admins is not None and full_admins != 1:
        blockers.append(
            f"{full_admins} full-access organization administrator(s) found; exactly one is required."
        )

    if saml_enabled is None:
        blockers.append(f"SAML status could not be verified ({safe_error(saml)}).")
    elif saml_enabled:
        blockers.append("SAML SSO is enabled.")

    # Extra safety gate beyond Meraki's minimum documented delete prerequisites.
    if license_count is None:
        reviews.append(f"License state could not be verified ({safe_error(licenses)}).")
    elif license_count > 0:
        blockers.append(f"Active/valuable licensing evidence found ({license_notes}).")
    elif license_state.get("expiredOnly"):
        reviews.append(
            f"Expired-only licensing found; not treated as active license value ({license_notes})."
        )

    if network_count is None:
        blockers.append(f"Networks could not be inventoried ({safe_error(networks)}).")
    elif network_count > 0:
        blockers.append(
            f"{network_count} network(s) still exist; Meraki requires zero networks before organization deletion."
        )

    if config_template_count is None:
        blockers.append(
            f"Configuration templates could not be verified ({safe_error(config_templates)})."
        )
    elif config_template_count > 0:
        blockers.append(
            f"{config_template_count} configuration template(s) still exist; they must be deleted first."
        )

    eligible = len(blockers) == 0

    audit = {
        "organizationId": org_id,
        "organizationName": org.get("name", ""),
        "networkCount": network_count,
        "configTemplateCount": config_template_count,
        "inventoryDeviceCount": inventory_count,
        "adminCount": admin_count,
        "fullAdminCount": full_admins,
        "samlEnabled": saml_enabled,
        "licenseActiveValueCount": license_count,
        "licenseExpiredOnly": license_state.get("expiredOnly", False),
        "licenseNotes": license_notes,
        "eligible": eligible,
        "blockers": blockers,
        "reviews": reviews,
        "endpointStatus": {
            "networks": networks.get("status"),
            "configTemplates": config_templates.get("status"),
            "inventory": inventory.get("status"),
            "admins": admins.get("status"),
            "saml": saml.get("status"),
            "licenses": licenses.get("status"),
        },
    }
    audit["classification"] = classify_org(audit)
    return audit


def display_name(org, index, public_display):
    return f"Organization {index:02d}" if public_display else org.get("name", "")


def print_audit(audit, public_display=False, index=None):
    name = (
        f"Organization {index:02d}"
        if public_display and index is not None
        else audit["organizationName"]
    )
    org_id = "[hidden]" if public_display else audit["organizationId"]

    print("\n" + "=" * 78)
    print(f"ORGANIZATION: {name} [{org_id}]")
    print("=" * 78)
    print(f"Networks:              {audit['networkCount'] if audit['networkCount'] is not None else 'UNKNOWN'}")
    print(f"Config templates:      {audit.get('configTemplateCount') if audit.get('configTemplateCount') is not None else 'UNKNOWN'}")
    print(f"Inventory devices:     {audit['inventoryDeviceCount'] if audit['inventoryDeviceCount'] is not None else 'UNKNOWN'}")
    print(f"Dashboard admins:      {audit['adminCount'] if audit['adminCount'] is not None else 'UNKNOWN'}")
    print(f"Full-access admins:    {audit['fullAdminCount'] if audit['fullAdminCount'] is not None else 'UNKNOWN'}")
    print(f"SAML enabled:          {bool_text(audit['samlEnabled'])}")
    print(f"Active license value:  {audit['licenseActiveValueCount'] if audit['licenseActiveValueCount'] is not None else 'UNKNOWN'}")
    print(f"Expired-only license:  {bool_text(audit['licenseExpiredOnly'])}")
    print(f"Classification:        {audit['classification']}")
    print(f"Deletion audit:        {'PASS' if audit['eligible'] else 'BLOCKED'}")

    if audit["blockers"]:
        print("\nBLOCKERS:")
        for item in audit["blockers"]:
            print(f"  [BLOCK] {item}")

    if audit["reviews"]:
        print("\nREVIEW:")
        for item in audit["reviews"]:
            print(f"  [REVIEW] {item}")

    if audit["classification"] == "READY FOR DELETE REVIEW":
        print("\nRESULT: READY FOR DELETE REVIEW.")
        print("        Deletion is permanent and still requires explicit --apply confirmation.")
    elif audit["classification"] == "SAFE AFTER ADMIN CLEANUP":
        print("\nRESULT: CLEANUP CANDIDATE - reduce dashboard admins to exactly one full-access admin, then re-audit.")
    elif audit["classification"] == "API ACCESS BLOCKED":
        print("\nRESULT: API ACCESS BLOCKED - the script cannot verify the required delete prerequisites.")
    elif audit["classification"] == "ACTIVE - DO NOT DELETE":
        print("\nRESULT: ACTIVE - DO NOT DELETE.")
    else:
        print("\nRESULT: CONFIG CLEANUP REQUIRED before deletion can be considered.")


def write_reports(audits, output_root):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = Path(output_root).expanduser().resolve() / f"Meraki-Org-Cleanup-Audit-{stamp}"
    folder.mkdir(parents=True, exist_ok=True)

    (folder / "organization-audit.json").write_text(
        json.dumps(audits, indent=2), encoding="utf-8"
    )

    csv_path = folder / "organization-audit.csv"
    fields = [
        "organizationName",
        "organizationId",
        "classification",
        "eligible",
        "networkCount",
        "inventoryDeviceCount",
        "adminCount",
        "fullAdminCount",
        "samlEnabled",
        "licenseActiveValueCount",
        "licenseExpiredOnly",
        "licenseNotes",
        "blockers",
        "reviews",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in audits:
            row = {k: a.get(k) for k in fields}
            row["blockers"] = " | ".join(a.get("blockers", []))
            row["reviews"] = " | ".join(a.get("reviews", []))
            w.writerow(row)

    return folder


def inspect_candidate(api, org, public_display=False, index=None):
    org_id = str(org["id"])
    networks = api.get_all(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/networks?perPage=1000",
        allow_error=True,
    )
    admins = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/admins",
        allow_error=True,
    )

    details = {
        "organizationId": org_id,
        "organizationName": org.get("name", ""),
        "networks": networks.get("data") if networks.get("ok") else None,
        "admins": admins.get("data") if admins.get("ok") else None,
        "networkStatus": networks.get("status"),
        "adminStatus": admins.get("status"),
    }

    label = f"Organization {index:02d}" if public_display and index else org.get("name", "")
    display_org_id = "[hidden]" if public_display else org_id

    print("\n" + "=" * 78)
    print(f"CANDIDATE DETAIL: {label} [{display_org_id}]")
    print("=" * 78)

    if networks.get("ok") and isinstance(networks.get("data"), list):
        print(f"Networks ({len(networks['data'])}):")
        for n_idx, network in enumerate(networks["data"], 1):
            name = f"Network {n_idx:02d}" if public_display else network.get("name", "")
            net_id = "[hidden]" if public_display else network.get("id", "")
            products = ", ".join(network.get("productTypes") or [])
            print(f"  {n_idx}. {name} [{net_id}]")
            print(f"     Products: {products or 'unknown'}")
            print(f"     Timezone: {network.get('timeZone') or 'unknown'}")
    else:
        print(f"Networks: unable to read ({safe_error(networks)})")

    print()

    if admins.get("ok") and isinstance(admins.get("data"), list):
        print(f"Dashboard administrators ({len(admins['data'])}):")
        for a_idx, admin in enumerate(admins["data"], 1):
            if public_display:
                name = f"Administrator {a_idx:02d}"
                email = "[hidden]"
                admin_id = "[hidden]"
            else:
                name = admin.get("name") or "(no name)"
                email = admin.get("email") or "(no email)"
                admin_id = admin.get("id") or ""
            print(f"  {a_idx}. {name}")
            print(f"     Email: {email}")
            print(f"     Org access: {admin.get('orgAccess') or 'unknown'}")
            print(f"     Admin ID: {admin_id}")
    else:
        print(f"Administrators: unable to read ({safe_error(admins)})")

    print("\nREAD-ONLY INSPECTION ONLY. Nothing was changed.")
    return details


def write_candidate_details(details, output_root):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = Path(output_root).expanduser().resolve() / f"Meraki-Org-Cleanup-Candidates-{stamp}"
    folder.mkdir(parents=True, exist_ok=True)

    (folder / "candidate-details.json").write_text(
        json.dumps(details, indent=2), encoding="utf-8"
    )

    with (folder / "candidate-networks.csv").open("w", newline="", encoding="utf-8-sig") as f:
        fields = ["organizationName", "organizationId", "networkName", "networkId", "productTypes", "timeZone"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for item in details:
            for n in item.get("networks") or []:
                w.writerow({
                    "organizationName": item.get("organizationName"),
                    "organizationId": item.get("organizationId"),
                    "networkName": n.get("name"),
                    "networkId": n.get("id"),
                    "productTypes": ",".join(n.get("productTypes") or []),
                    "timeZone": n.get("timeZone"),
                })

    with (folder / "candidate-admins.csv").open("w", newline="", encoding="utf-8-sig") as f:
        fields = ["organizationName", "organizationId", "adminName", "email", "orgAccess", "adminId"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for item in details:
            for a in item.get("admins") or []:
                w.writerow({
                    "organizationName": item.get("organizationName"),
                    "organizationId": item.get("organizationId"),
                    "adminName": a.get("name"),
                    "email": a.get("email"),
                    "orgAccess": a.get("orgAccess"),
                    "adminId": a.get("id"),
                })
    return folder


def select_candidate_for_admin_cleanup(api, orgs, public_display=False):
    candidates = []

    print(f"\nAuditing {len(orgs)} organizations to find admin-cleanup candidates...")
    for index, org in enumerate(orgs, 1):
        audit = audit_org(api, org)
        if audit.get("classification") == "SAFE AFTER ADMIN CLEANUP":
            candidates.append((index, org, audit))

    if not candidates:
        raise SystemExit("No SAFE AFTER ADMIN CLEANUP candidates were found.")

    print("\nAdmin-cleanup candidates:")
    for item_index, (org_index, org, audit) in enumerate(candidates, 1):
        label = (
            f"Organization {org_index:02d}"
            if public_display
            else org.get("name", "")
        )
        org_id = "[hidden]" if public_display else org.get("id")
        print(
            f"  {item_index}. {label} [{org_id}] "
            f"- {audit.get('adminCount')} admins, "
            f"{audit.get('networkCount')} network(s)"
        )

    while True:
        raw = input(f"Select candidate [1-{len(candidates)}]: ").strip()
        try:
            selected = int(raw)
            if 1 <= selected <= len(candidates):
                return candidates[selected - 1]
        except ValueError:
            pass
        print("Invalid selection.")


def build_admin_cleanup_plan(api, org, public_display=False):
    org_id = str(org["id"])
    result = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/admins",
        allow_error=True,
    )
    if not result.get("ok") or not isinstance(result.get("data"), list):
        raise SystemExit(
            f"Could not read organization administrators ({safe_error(result)})."
        )

    admins = result["data"]
    if len(admins) <= 1:
        raise SystemExit("This organization already has one or fewer administrators.")

    full_admins = [a for a in admins if a.get("orgAccess") == "full"]
    if not full_admins:
        raise SystemExit("No full-access administrator was found. Cleanup is blocked.")

    print("\nAdministrators:")
    for idx, admin in enumerate(admins, 1):
        if public_display:
            name = f"Administrator {idx:02d}"
            email = "[hidden]"
        else:
            name = admin.get("name") or "(no name)"
            email = admin.get("email") or "(no email)"
        print(
            f"  {idx}. {name} | {email} | "
            f"orgAccess={admin.get('orgAccess') or 'unknown'}"
        )

    while True:
        raw = input(f"Select the ONE administrator to KEEP [1-{len(admins)}]: ").strip()
        try:
            keep_index = int(raw)
            if 1 <= keep_index <= len(admins):
                keep_admin = admins[keep_index - 1]
                break
        except ValueError:
            pass
        print("Invalid selection.")

    if keep_admin.get("orgAccess") != "full":
        raise SystemExit(
            "Cleanup blocked: the administrator you selected to keep is not full-access."
        )

    remove_admins = [a for a in admins if a.get("id") != keep_admin.get("id")]

    return {
        "organization": {
            "id": org_id,
            "name": org.get("name", ""),
        },
        "keepAdmin": keep_admin,
        "removeAdmins": remove_admins,
    }


def print_admin_cleanup_plan(plan, public_display=False):
    org = plan["organization"]
    org_name = "[hidden]" if public_display else org["name"]
    org_id = "[hidden]" if public_display else org["id"]
    keep = plan["keepAdmin"]

    print("\n" + "=" * 78)
    print("ADMIN CLEANUP PLAN")
    print("=" * 78)
    print(f"Organization: {org_name} [{org_id}]")

    if public_display:
        print("KEEP:   Administrator [hidden] (full access)")
    else:
        print(
            f"KEEP:   {keep.get('name') or '(no name)'} "
            f"<{keep.get('email') or '(no email)'}> "
            f"[{keep.get('id')}]"
        )

    print("\nREMOVE:")
    for idx, admin in enumerate(plan["removeAdmins"], 1):
        if public_display:
            print(f"  {idx}. Administrator [hidden]")
        else:
            print(
                f"  {idx}. {admin.get('name') or '(no name)'} "
                f"<{admin.get('email') or '(no email)'}> "
                f"[{admin.get('id')}]"
            )

    print("\nNetworks and devices are NOT changed by this operation.")


def apply_admin_cleanup(api, org, plan):
    org_id = str(org["id"])

    # Re-read admins immediately before making any destructive change.
    latest = api.get(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/admins",
        allow_error=True,
    )
    if not latest.get("ok") or not isinstance(latest.get("data"), list):
        raise SystemExit(
            f"Could not re-verify administrators ({safe_error(latest)}). Nothing changed."
        )

    current_by_id = {
        str(a.get("id")): a
        for a in latest["data"]
        if a.get("id") is not None
    }

    keep_id = str(plan["keepAdmin"].get("id"))
    if keep_id not in current_by_id:
        raise SystemExit("The selected keep-admin no longer exists. Nothing changed.")

    if current_by_id[keep_id].get("orgAccess") != "full":
        raise SystemExit(
            "The selected keep-admin is no longer full-access. Nothing changed."
        )

    remove_ids = [str(a.get("id")) for a in plan["removeAdmins"]]
    missing = [admin_id for admin_id in remove_ids if admin_id not in current_by_id]
    if missing:
        raise SystemExit(
            "Administrator membership changed since the plan was built. "
            "Re-run the plan before applying."
        )

    if len(latest["data"]) - len(remove_ids) != 1:
        raise SystemExit(
            "Safety check failed: this cleanup would not leave exactly one administrator."
        )

    removed = []
    for admin_id in remove_ids:
        result = api.delete(
            f"/organizations/{urllib.parse.quote(org_id, safe='')}/admins/"
            f"{urllib.parse.quote(admin_id, safe='')}",
            allow_error=True,
        )
        if not result.get("ok"):
            raise SystemExit(
                f"Admin cleanup stopped after removing {len(removed)} admin(s). "
                f"Delete failed with {safe_error(result)}. Re-audit before continuing."
            )
        removed.append(admin_id)

    return removed


def select_network_cleanup_candidate(api, orgs, public_display=False):
    candidates = []
    print(f"\nAuditing {len(orgs)} organizations to find network-cleanup candidates...")

    for index, org in enumerate(orgs, 1):
        audit = audit_org(api, org)
        if (
            audit.get("inventoryDeviceCount") == 0
            and audit.get("adminCount") == 1
            and audit.get("fullAdminCount") == 1
            and audit.get("samlEnabled") is False
            and audit.get("licenseActiveValueCount") == 0
            and (audit.get("networkCount") or 0) > 0
            and audit.get("configTemplateCount") == 0
        ):
            candidates.append((index, org, audit))

    if not candidates:
        raise SystemExit("No network-cleanup candidates were found.")

    print("\nNetwork-cleanup candidates:")
    for item_index, (org_index, org, audit) in enumerate(candidates, 1):
        label = f"Organization {org_index:02d}" if public_display else org.get("name", "")
        org_id = "[hidden]" if public_display else org.get("id")
        print(
            f"  {item_index}. {label} [{org_id}] - "
            f"{audit.get('networkCount')} network(s), 0 inventory devices"
        )

    while True:
        raw = input(f"Select candidate [1-{len(candidates)}]: ").strip()
        try:
            selected = int(raw)
            if 1 <= selected <= len(candidates):
                return candidates[selected - 1]
        except ValueError:
            pass
        print("Invalid selection.")


def build_network_cleanup_plan(api, org, public_display=False):
    org_id = str(org["id"])
    result = api.get_all(
        f"/organizations/{urllib.parse.quote(org_id, safe='')}/networks?perPage=1000",
        allow_error=True,
    )
    if not result.get("ok") or not isinstance(result.get("data"), list):
        raise SystemExit(f"Could not read organization networks ({safe_error(result)}).")

    networks = result["data"]
    if not networks:
        raise SystemExit("This organization has no networks to remove.")

    print("\nNetworks scheduled for PERMANENT deletion:")
    for idx, network in enumerate(networks, 1):
        name = f"Network {idx:02d}" if public_display else network.get("name", "")
        network_id = "[hidden]" if public_display else network.get("id", "")
        products = ", ".join(network.get("productTypes") or [])
        print(f"  {idx}. {name} [{network_id}]")
        print(f"     Products: {products or 'unknown'}")
        print(f"     Timezone: {network.get('timeZone') or 'unknown'}")

    return networks


def apply_network_cleanup(api, networks):
    deleted = []
    for network in networks:
        network_id = str(network.get("id"))
        result = api.delete(
            f"/networks/{urllib.parse.quote(network_id, safe='')}",
            allow_error=True,
        )
        if not result.get("ok"):
            return {
                "ok": False,
                "deleted": deleted,
                "failedNetwork": network,
                "error": safe_error(result),
            }
        deleted.append(network)
    return {"ok": True, "deleted": deleted}


def get_api_key():
    key = (
        os.getenv("MERAKI_DASHBOARD_API_KEY")
        or os.getenv("MERAKI_API_KEY")
    )
    if key:
        return key.strip()
    print("No Meraki API key environment variable was found.")
    return getpass.getpass("Enter Meraki Dashboard API key: ").strip()


def select_org(orgs, public_display):
    print("\nAvailable organizations:")
    for i, org in enumerate(orgs, 1):
        label = display_name(org, i, public_display)
        org_id = "[hidden]" if public_display else org.get("id")
        print(f"  {i:>3}. {label}  [{org_id}]")

    while True:
        raw = input(f"Select organization [1-{len(orgs)}]: ").strip()
        try:
            idx = int(raw)
            if 1 <= idx <= len(orgs):
                return idx, orgs[idx - 1]
        except ValueError:
            pass
        print("Invalid selection.")


def main():
    parser = argparse.ArgumentParser(
        description="Audit Meraki organizations before permanent deletion."
    )
    parser.add_argument(
        "--audit-all",
        action="store_true",
        help="Audit every accessible organization. No organizations are deleted.",
    )
    parser.add_argument(
        "--inspect-candidates",
        action="store_true",
        help="Audit all organizations, then list networks and admins for SAFE AFTER ADMIN CLEANUP candidates. Read-only.",
    )
    parser.add_argument(
        "--plan-admin-cleanup",
        action="store_true",
        help="Build a read-only plan to reduce one cleanup candidate to one full-access administrator.",
    )
    parser.add_argument(
        "--apply-admin-cleanup",
        action="store_true",
        help="Remove extra organization administrators after an interactive plan and explicit confirmation.",
    )
    parser.add_argument(
        "--plan-network-cleanup",
        action="store_true",
        help="Build a read-only plan to permanently remove networks from an otherwise clean organization.",
    )
    parser.add_argument(
        "--apply-network-cleanup",
        action="store_true",
        help="Permanently delete networks from an otherwise clean organization after explicit confirmation.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Allow permanent deletion of one organization after it passes all automated blockers.",
    )
    parser.add_argument(
        "--public-display",
        action="store_true",
        help="Hide organization names and IDs from console output.",
    )
    parser.add_argument(
        "--output",
        default=str(Path.home() / "Documents" / "Meraki-Org-Cleanup-Reports"),
        help="Folder used for audit reports.",
    )
    args = parser.parse_args()

    selected_modes = sum(
        bool(x)
        for x in (
            args.audit_all,
            args.inspect_candidates,
            args.plan_admin_cleanup,
            args.apply_admin_cleanup,
            args.plan_network_cleanup,
            args.apply_network_cleanup,
            args.apply,
        )
    )
    if selected_modes > 1:
        raise SystemExit(
            "--audit-all, --inspect-candidates, --plan-admin-cleanup, "
            "--apply-admin-cleanup, --plan-network-cleanup, "
            "--apply-network-cleanup, and --apply are mutually exclusive."
        )

    api_key = get_api_key()
    if not api_key:
        raise SystemExit("No API key supplied.")

    api = MerakiAPI(api_key)

    print("\nMERAKI ORGANIZATION CLEANUP - SAFE WRAPPER")
    print("=" * 78)
    print("Mode:", "APPLY" if args.apply else "AUDIT / DRY RUN")
    if not args.apply:
        print("No organization will be deleted.")

    org_result = api.get("/organizations", allow_error=True)
    if not org_result.get("ok"):
        status = org_result.get("status")
        detail = (org_result.get("error") or "").strip()
        print("\nMERAKI API CONNECTION FAILED")
        print("=" * 78)
        print(f"HTTP status: {status if status is not None else 'unknown'}")
        if status == 401:
            print("Meraki rejected the API key. Re-copy the key from Dashboard and try again.")
        elif status == 403:
            print("The API key authenticated, but this account is not permitted to list organizations.")
        elif status == 400:
            print("Meraki rejected the request as a bad request.")
            print(f"Python received an API key length of {len(api_key)} characters.")
            print("V6 uses the same X-Cisco-Meraki-API-Key method that was validated successfully in PowerShell.")
        else:
            print("Meraki did not return the organization list.")
        if detail:
            print(f"Response: {detail}")
        raise SystemExit("\nNothing was changed.")

    orgs = sorted(org_result.get("data") or [], key=lambda o: o.get("name", "").lower())
    if not orgs:
        raise SystemExit("No organizations were returned for this API key.")

    if args.plan_network_cleanup or args.apply_network_cleanup:
        org_index, org, audit = select_network_cleanup_candidate(
            api, orgs, public_display=args.public_display
        )
        networks = build_network_cleanup_plan(
            api, org, public_display=args.public_display
        )

        print("\n" + "=" * 78)
        print("NETWORK CLEANUP PLAN")
        print("=" * 78)
        print(f"Networks to permanently delete: {len(networks)}")
        print("Deleting these networks is irreversible and removes their configuration.")

        if args.plan_network_cleanup:
            print("\nDRY RUN ONLY. NO NETWORKS WERE DELETED.")
            return

        if args.public_display:
            raise SystemExit(
                "\nNETWORK CLEANUP BLOCKED: --public-display is recording/demo mode only."
            )

        print("\n" + "!" * 78)
        print("NETWORK CLEANUP APPLY MODE")
        print("!" * 78)
        print(f"Organization: {org.get('name')} [{org.get('id')}]")
        print("Every network listed above will be permanently deleted.")

        confirm_name = input("\nType the EXACT organization name to continue: ").strip()
        if confirm_name != org.get("name"):
            raise SystemExit("Confirmation failed. Nothing was changed.")

        phrase = input("Type DELETE NETWORKS to continue: ").strip()
        if phrase != "DELETE NETWORKS":
            raise SystemExit("Confirmation failed. Nothing was changed.")

        outcome = apply_network_cleanup(api, networks)
        if not outcome.get("ok"):
            failed = outcome.get("failedNetwork") or {}
            print(
                f"\nNetwork cleanup stopped after deleting "
                f"{len(outcome.get('deleted') or [])} network(s)."
            )
            print(
                f"Failed network: {failed.get('name') or '(unknown)'} "
                f"[{failed.get('id') or ''}]"
            )
            raise SystemExit(
                f"Meraki returned {outcome.get('error')}. Re-audit before continuing."
            )

        print(f"\nDeleted {len(outcome.get('deleted') or [])} network(s).")
        print("\nRe-auditing organization...")
        updated = audit_org(api, org)
        print_audit(updated, public_display=False, index=org_index)

        if updated.get("classification") == "READY FOR DELETE REVIEW":
            print(
                "\nSUCCESS: The organization is now READY FOR DELETE REVIEW. "
                "It has NOT been deleted."
            )
        else:
            print(
                "\nNetwork cleanup completed, but the organization is not yet ready "
                "for delete review. Resolve any remaining findings first."
            )
        return

    if args.plan_admin_cleanup or args.apply_admin_cleanup:
        org_index, org, audit = select_candidate_for_admin_cleanup(
            api, orgs, public_display=args.public_display
        )

        plan = build_admin_cleanup_plan(
            api, org, public_display=args.public_display
        )
        print_admin_cleanup_plan(plan, public_display=args.public_display)

        if args.plan_admin_cleanup:
            print("\nDRY RUN ONLY. NO ADMINISTRATORS WERE REMOVED.")
            return

        if args.public_display:
            raise SystemExit(
                "\nADMIN CLEANUP BLOCKED: --public-display is recording/demo mode only. "
                "Remove it for a real destructive operation."
            )

        print("\n" + "!" * 78)
        print("ADMIN CLEANUP APPLY MODE")
        print("!" * 78)
        print("This will revoke organization access for every admin in REMOVE.")
        print("The selected KEEP administrator will remain full-access.")

        confirm_name = input("\nType the EXACT organization name to continue: ").strip()
        if confirm_name != org.get("name"):
            raise SystemExit("Confirmation failed. Nothing was changed.")

        phrase = input("Type REMOVE EXTRA ADMINS to continue: ").strip()
        if phrase != "REMOVE EXTRA ADMINS":
            raise SystemExit("Confirmation failed. Nothing was changed.")

        removed = apply_admin_cleanup(api, org, plan)
        print(f"\nRemoved {len(removed)} extra administrator(s).")

        print("\nRe-auditing organization...")
        updated = audit_org(api, org)
        print_audit(updated, public_display=False, index=org_index)

        if updated.get("classification") == "READY FOR DELETE REVIEW":
            print(
                "\nSUCCESS: The organization is now READY FOR DELETE REVIEW. "
                "It has NOT been deleted."
            )
        else:
            print(
                "\nAdmin cleanup completed, but the organization is not yet ready "
                "for delete review. Resolve the remaining findings first."
            )
        return

    if args.inspect_candidates:
        audits = []
        org_lookup = {}

        print(f"\nAuditing {len(orgs)} organizations to find cleanup candidates...")
        for i, org in enumerate(orgs, 1):
            audit = audit_org(api, org)
            audits.append(audit)
            org_lookup[str(org["id"])] = (i, org)

        candidates = [
            a for a in audits
            if a.get("classification") == "SAFE AFTER ADMIN CLEANUP"
        ]

        print("\n" + "=" * 78)
        print("CANDIDATE SUMMARY")
        print("=" * 78)
        print(f"Organizations audited: {len(audits)}")
        print(f"SAFE AFTER ADMIN CLEANUP: {len(candidates)}")

        if not candidates:
            print("\nNo cleanup candidates were found.")
            print("NO CHANGES WERE MADE.")
            return

        details = []
        for audit in candidates:
            idx, org = org_lookup[audit["organizationId"]]
            details.append(
                inspect_candidate(
                    api,
                    org,
                    public_display=args.public_display,
                    index=idx,
                )
            )

        folder = write_candidate_details(details, args.output)
        print("\n" + "=" * 78)
        print("INSPECTION COMPLETE")
        print("=" * 78)
        print(f"Candidate detail report:\n  {folder}")
        print("\nNO CHANGES WERE MADE.")
        return

    if args.audit_all:
        audits = []
        print(f"\nAuditing {len(orgs)} organizations...")
        for i, org in enumerate(orgs, 1):
            print(f"\n[{i}/{len(orgs)}] Auditing {display_name(org, i, args.public_display)}...")
            audit = audit_org(api, org)
            audits.append(audit)
            print_audit(audit, public_display=args.public_display, index=i)

        report_folder = write_reports(audits, args.output)
        classifications = {}
        for a in audits:
            classifications[a["classification"]] = classifications.get(a["classification"], 0) + 1

        print("\n" + "=" * 78)
        print("AUDIT SUMMARY")
        print("=" * 78)
        print(f"Organizations audited:          {len(audits)}")
        for label in (
            "READY FOR DELETE REVIEW",
            "SAFE AFTER ADMIN CLEANUP",
            "CONFIG CLEANUP REQUIRED",
            "API ACCESS BLOCKED",
            "ACTIVE - DO NOT DELETE",
        ):
            print(f"{label + ':':<32} {classifications.get(label, 0)}")
        print(f"Report folder:\n  {report_folder}")
        print("\nNO ORGANIZATIONS WERE DELETED.")
        return

    selected_index, org = select_org(orgs, args.public_display)
    audit = audit_org(api, org)
    print_audit(audit, public_display=args.public_display, index=selected_index)

    report_folder = write_reports([audit], args.output)
    print(f"\nAudit report saved to:\n  {report_folder}")

    if not args.apply:
        print("\nNO ORGANIZATION WAS DELETED.")
        if audit["eligible"]:
            print("If you intentionally want to delete this organization, rerun with --apply.")
        return

    if not audit["eligible"]:
        raise SystemExit("\nDELETE BLOCKED: The organization did not pass the automated safety checks.")

    # Deliberately do not support public-display for destructive execution.
    if args.public_display:
        raise SystemExit(
            "\nDELETE BLOCKED: --public-display is recording/demo mode only. "
            "Remove it for a real destructive operation."
        )

    print("\n" + "!" * 78)
    print("PERMANENT DELETE MODE")
    print("!" * 78)
    print(f"Organization: {org.get('name')} [{org.get('id')}]")
    print("This action is NON-REVERSIBLE.")
    print("Any remaining network configuration in this organization will be lost.")
    print("The script will NOT move licenses, devices, admins, or configuration for you.")

    confirm_name = input("\nType the EXACT organization name to continue: ").strip()
    if confirm_name != org.get("name"):
        raise SystemExit("Confirmation failed. Nothing was deleted.")

    phrase = input('Type DELETE ORGANIZATION to permanently delete it: ').strip()
    if phrase != "DELETE ORGANIZATION":
        raise SystemExit("Confirmation failed. Nothing was deleted.")

    result = api.delete(
        f"/organizations/{urllib.parse.quote(str(org['id']), safe='')}",
        allow_error=True,
    )

    if not result["ok"]:
        raise SystemExit(
            f"Delete request failed with {safe_error(result)}. "
            "Nothing further was changed by this script."
        )

    print("\nORGANIZATION DELETED")
    print(f"Name: {org.get('name')}")
    print("Meraki returned a successful delete response.")
    print("Refresh Dashboard before taking any additional action.")


if __name__ == "__main__":
    main()
