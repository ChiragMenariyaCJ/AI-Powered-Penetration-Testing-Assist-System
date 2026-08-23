# Scanning and Findings

Scanning records describe requested assessment stages. Execution services run
scoped Nmap commands, preserve their output, and translate evidence into finding
records.

## Scan lifecycle

1. A scan record connects a project and target with a scan type and status.
2. `POST /api/scans/execute/{scan_id}` loads the scan and validates its related
   records.
3. `NmapService` builds argument lists without invoking a shell and executes only
   the supported stage.
4. The execution use case records output and final status.
5. `VulnerabilityParser` converts supported evidence into normalized
   vulnerability records.

The terminal workflow presents scoped stages one at a time. It does not execute
recommendations and does not replace the authorization check.

The optional CVE stage is optimized for an interactive student session: it scans
Nmap's common-port set, runs only the safe external `vulners` correlation script,
and limits each script invocation to 30 seconds. This is intentionally faster
than running every script in Nmap's broad `vuln and safe` categories.

## Findings

Vulnerability endpoints support individual records, filtered lists, and summary
counts by severity. A finding records the observed host/service evidence and
severity used by recommendation and reporting features.

Not every stored finding is a proven vulnerability:

- `EXPOSED_SERVICE` means Nmap directly observed an open port and identified a
  probable service. Its severity is a hard-coded review priority, not a CVSS
  score or proof that the service is exploitable.
- `CVE_CANDIDATE` means Vulners correlated a detected product/version or CPE with
  published CVEs. Distribution patches and fingerprint uncertainty can make the
  match inapplicable, so it requires manual verification.
- `CONFIRMED_CVE` is used only when an Nmap script explicitly reports a
  `VULNERABLE` state. It is stronger evidence, but should still be validated
  before making a final report claim.

## Main code

- Scan CRUD: `scan_routes.py`, `scan_usecase.py`, `scan_repository.py`
- Execution: `scan_execution_routes.py`, `scan_execution_usecase.py`
- Nmap adapter: `Backend/services/nmap_service.py`
- Service-aware checks: `Backend/services/service_scan_service.py`
- Evidence parsing: `Backend/services/vulnerability_parser.py`
- Findings: `vulnerability_routes.py`, `vulnerability_usecase.py`, and
  `vulnerability_repository.py`

Only explicitly authorized training targets should be scanned. The restricted
lab workflow has additional host-only-network, identity, snapshot, and
fingerprint checks described in [Access testing](../access-testing.md).
