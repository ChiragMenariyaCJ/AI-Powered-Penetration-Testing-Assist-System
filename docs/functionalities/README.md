# PTAS Functionality Guides

These guides group the code by user-facing behavior rather than by Python
folder. Use them when explaining a feature from beginning to end.

| Functionality | Guide | Main result |
| --- | --- | --- |
| Registration and login | [Authentication](authentication.md) | User record and access token |
| Projects, scope, and targets | [Projects, scope, and targets](projects-scope-targets.md) | Authorized assessment boundary |
| Scan execution and findings | [Scanning and findings](scanning-and-findings.md) | Nmap evidence and vulnerability records |
| Guidance and reporting | [Recommendations and reports](recommendations-and-reports.md) | Advisory actions and exported evidence |

All features follow the layer flow documented in
[Architecture and request flow](../architecture.md). Endpoint details can also
be explored interactively at `http://127.0.0.1:8000/docs` while the API runs.
