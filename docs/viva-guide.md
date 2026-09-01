# PTAS Viva Explanation Guide

This guide is a map for understanding the submitted code. It is not a script to
memorise. Open the named files, follow one request yourself, and explain the
system in your own words.

## One-sentence explanation

PTAS is a terminal-first assistant that collects evidence from an explicitly
authorised target, stores structured findings, uses rules or a local LLM to
suggest a human-reviewed next step, and generates repeatable reports.

## The main execution path

```text
Student terminal
      |
      v
API route -> controller -> use case -> repository -> database
                              |
                              +-> scanner / parser / advisor / report service
```

- `Backend/routes/` defines HTTP paths and validates request data.
- `Backend/controllers/` connects a route to the required use case.
- `Backend/usecases/` contains business rules and coordinates operations.
- `Backend/repositories/` contains database queries.
- `Backend/models/` defines database tables.
- `Backend/schemas/` defines API input and output shapes.
- `Backend/services/` handles Nmap, parsing, recommendations, lab verification,
  and HTML rendering.
- `Backend/terminal_workflow.py` controls the guided student conversation.
- `Backend/terminal_assistant/` reads terminal evidence and displays advice.

The layers are not separate applications. They divide one request into small
responsibilities so a database query, business rule, and HTTP response are not
mixed in one large function.

## Where AI is actually used

The local Ollama model is optional. When `PTAS_LLM_PROVIDER=ollama`, PTAS sends
sanitised assessment evidence to the configured local model, currently
`qwen2.5:3b-instruct`. The model proposes a next command and explanation.

Deterministic Python code still:

- checks the authorised scope;
- runs and times out scanning tools;
- parses tool output;
- stores findings;
- rejects unsuitable model output;
- rejects unsuitable model output without replacing it with static advice; and
- renders the report.

Therefore, do not say that the LLM performs the penetration test. It assists
planning. The student chooses whether to run a displayed command.

## Research question 1

**How can AI assist penetration testers during vulnerability assessment and
exploitation planning?**

PTAS demonstrates assistance by turning observed ports, services, versions,
CVE candidates, and command output into a prioritised explanation and a next
step. The useful contribution is context selection: the recommendation is based
on current evidence instead of being a generic chatbot answer. Scope checks and
manual approval keep the tester in control.

Evidence in the project:

- `Backend/terminal_assistant/analyzer.py` extracts structured evidence.
- `Backend/terminal_assistant/advisor.py` calls Ollama and interprets its reply.
- `Backend/services/ai_recommendation_engine.py` requests and scores validated
  Ollama recommendations.
- `Backend/terminal_assistant/scope_guard.py` checks targets against scope.

## Research question 2

**Can AI-generated attack recommendations improve penetration-testing
efficiency?**

The implementation makes this possible to test, but the code alone does not
prove improvement. A defensible evaluation compares a manual workflow with the
PTAS-assisted workflow on the same isolated lab tasks.

Measure at least:

- time to choose the first valid next step;
- total task-completion time;
- number of irrelevant or repeated commands;
- percentage of recommendations accepted by the tester;
- technically correct recommendations; and
- unsafe or out-of-scope recommendations rejected by PTAS.

Report the measured results even if the improvement is small. Do not claim that
one successful demonstration proves general effectiveness.

## Research question 3

**How effective is automated reporting compared with manual reporting?**

PTAS creates JSON and HTML from the same stored scan and finding records. This
should improve speed, formatting consistency, and traceability. It does not
guarantee that every finding is correct or that business impact is understood.
A tester still reviews the final report.

A fair comparison measures:

- time required to produce the report;
- number of required sections completed;
- consistency between repeated runs;
- factual errors or missing evidence; and
- time needed for human correction.

The relevant implementation is in `Backend/usecases/report_usecase.py` and
`Backend/services/html_report_renderer.py`.

## Findings: what is real and what is inferred

- An open port or service parsed directly from Nmap is observed evidence.
- A detected version is evidence reported by the scanner, but can still be
  inaccurate if a service disguises itself.
- A CVE match is a correlation candidate, not proof that exploitation works.
- An LLM recommendation is advice, not a verified vulnerability.
- A generated severity or priority is a system judgement and should be reviewed.

This distinction is important during the demonstration.

## Likely questions

### Why use a local Ollama model?

It keeps assessment evidence on the local machine, avoids an external API key,
and supports an offline lab. The trade-off is that a small local model may
return weaker or malformed suggestions.

### What happens when Ollama is unavailable?

PTAS reports that no AI recommendation was generated. It does not replace the
missing model output with static advice or present deterministic text as AI.

### Why use FastAPI when the interface is a terminal?

The API separates the user interface from application logic, provides typed
validation and Swagger documentation, and makes the same backend available to a
future web interface. The terminal uses the API rather than bypassing it.

### What are the main limitations?

Results depend on scanner accuracy, the current vulnerability data, model
quality, and the lab configuration. PTAS does not prove exploitability from a
CVE match, does not replace tester judgement, and has only been evaluated on the
targets included in the study.

### What would you improve next?

Use a recorded evaluation dataset, compare multiple local models and a manual
baseline, add database migrations, improve recommendation deduplication, and
measure report accuracy with independent reviewers.

## A short demonstration order

1. Start the API and show one traced request.
2. Log in and select a project.
3. Explain scope and target authorisation.
4. Run one scan stage and identify observed evidence.
5. Show one recommendation with its Ollama provider label.
6. Explain that the command requires human approval.
7. Generate the JSON and HTML report.
8. Run one focused test and explain Arrange, Act, Assert.

If you cannot explain a feature after following this path, remove or simplify
that feature because it is outside the dissertation scope—not because it looks
too professional.
