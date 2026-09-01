# Recommendations and Reports

Recommendations turn collected evidence into suggested next steps. Reports
package assessment metadata, findings, and recommendation decisions for review.

## Recommendations

The recommendation use case loads a vulnerability, requests guidance from the
configured local Ollama model, and supports approval or rejection. If Ollama is
unavailable or its response fails validation, PTAS produces no recommendation.
Recommendations are advisory and are never executed automatically.

The right-hand terminal pane uses a separate assistant pipeline. It follows a
sanitized transcript, detects useful evidence, checks scope and safety rules,
and renders one readable recommendation at a time.

## Reports

The report use case collects the scan, vulnerability summary, and recommendation
summary. `HtmlReportRenderer` creates an escaped HTML representation, while
export endpoints return the requested supported format and stored report
metadata.

## Main code

- Recommendations: `recommendation_routes.py`, `recommendation_usecase.py`,
  `recommendation_repository.py`, and
  `Backend/services/ai_recommendation_engine.py`
- Terminal guidance: `Backend/terminal_assistant/`
- Reports: `report_routes.py`, `report_usecase.py`, `report_repository.py`, and
  `Backend/services/html_report_renderer.py`

Approval records a human decision; it is not permission for PTAS to run the
suggested command.
