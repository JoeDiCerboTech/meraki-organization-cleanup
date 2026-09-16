# Meraki Organization Cleanup

A guarded Python workflow for auditing and safely removing obsolete Cisco Meraki organizations.

The script is intentionally conservative. It starts in audit mode, classifies organizations, blocks deletion when required prerequisites are not met, and requires deliberate confirmations before destructive actions.

## What it checks

- Networks
- Configuration templates
- Inventory devices
- Dashboard administrators
- Full-access administrator count
- SAML status
- License state
- API accessibility

It also surfaces Meraki API error responses so hidden blockers, such as an MDM domain binding, can be identified instead of silently ignored.

## Safety model

The script does **not** blindly delete organizations.

Key protections include:

- Audit / dry-run behavior by default
- Active organizations are blocked
- API-access failures are blocked
- Organizations with devices are blocked
- Active licensing evidence is blocked
- SAML-enabled organizations are blocked
- Remaining networks and configuration templates are blocked
- Exactly one full-access administrator is required
- Destructive modes require exact typed confirmation
- `--public-display` masks organization names and IDs and blocks destructive operations

## Requirements

- Python 3.10+
- A Cisco Meraki Dashboard API key
- No third-party Python packages are required

The script uses only the Python standard library.

## API key

You can either set the API key as an environment variable or enter it interactively when prompted.

PowerShell:

```powershell
$env:MERAKI_DASHBOARD_API_KEY = "YOUR_API_KEY"
```

Do not commit API keys to GitHub.

## Audit all organizations

```powershell
python .\meraki-organization-cleanup.py --audit-all
```

This is read-only.

## Inspect cleanup candidates

```powershell
python .\meraki-organization-cleanup.py --inspect-candidates
```

This lists the networks and administrators for organizations classified as cleanup candidates.

## Plan administrator cleanup

```powershell
python .\meraki-organization-cleanup.py --plan-admin-cleanup
```

Read-only. It shows which administrator would remain and which extra administrators would be removed.

To apply the administrator cleanup:

```powershell
python .\meraki-organization-cleanup.py --apply-admin-cleanup
```

## Plan network cleanup

```powershell
python .\meraki-organization-cleanup.py --plan-network-cleanup
```

Read-only. It shows the networks that would be permanently removed.

To apply the network cleanup:

```powershell
python .\meraki-organization-cleanup.py --apply-network-cleanup
```

## Delete an organization

Only after the organization passes the final audit:

```powershell
python .\meraki-organization-cleanup.py --apply
```

The script requires the exact organization name and the confirmation phrase:

```text
DELETE ORGANIZATION
```

before sending the permanent delete request.

## Public / recording mode

For screenshots, demos, or videos:

```powershell
python .\meraki-organization-cleanup.py --audit-all --public-display
```

This masks organization names and IDs in console output. Destructive operations are blocked while `--public-display` is enabled.

## Important

Organization and network deletion is permanent. Review the audit output and Cisco Meraki documentation before removing production configuration.

This project is not affiliated with or endorsed by Cisco or Meraki.

## License

MIT
