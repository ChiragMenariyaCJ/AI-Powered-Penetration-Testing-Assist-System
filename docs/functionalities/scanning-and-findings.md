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

## Findings

Vulnerability endpoints support individual records, filtered lists, and summary
counts by severity. A finding records the observed host/service evidence and
severity used by recommendation and reporting features.

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
