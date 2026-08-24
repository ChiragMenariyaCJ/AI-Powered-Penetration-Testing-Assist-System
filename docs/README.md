# PTAS Documentation

This folder is the single entry point for project documentation. The root
`README.md` stays short; detailed explanations live here so each subject has one
maintained source.

## Getting started

- [Setup and running](setup-and-running.md) — installation, configuration,
  startup, tests, production options, and troubleshooting.
- [Terminal workflow](terminal-workflow.md) — the two-pane student workspace,
  commands, recommendation behavior, and safety boundaries.
- [Restricted access-testing lab](access-testing.md) — isolated Metasploitable 2
  setup and guarded teaching exercises.
- [Metasploitable setup by IP](metasploitable/README.md) — configure separate
  Kali and Metasploitable VMware guests without a host `.vmx` path.

## Understanding the code

- [Architecture and request flow](architecture.md) — how a request travels from
  FastAPI through controllers, use cases, repositories, and services.
- [Functionality index](functionalities/README.md) — feature-by-feature guides
  for authentication, projects, targets, scanning, findings, recommendations,
  and reports.
- [Viva explanation guide](viva-guide.md) — the smallest code map, research
  question evidence, limitations, and likely presentation questions.

## Suggested reading order

1. Read **Setup and running** to launch the application.
2. Read **Architecture and request flow** to understand the folder layers.
3. Open the relevant functionality guide before explaining or modifying a
   feature.
4. Use descriptive function names and nearby comments in VS Code to follow an
   individual operation.
