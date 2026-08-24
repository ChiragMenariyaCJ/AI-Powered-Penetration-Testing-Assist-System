# PTAS Test Suite

The tests verify that PTAS behaves consistently when its backend, terminal
assistant, and student workflow change. They are regression tests: if a future
change breaks an existing behavior, the relevant test should fail and identify
what needs investigation.

## Safety and isolation

Running these tests does not scan a real target and does not require the PTAS API,
MariaDB, Nmap, Metasploitable, or Ollama to be running.

- Database tests create a fresh in-memory SQLite database for each test.
- Nmap and Ollama responses are replaced with controlled test doubles.
- HTTP calls are mocked instead of being sent to external services.
- Temporary reports, transcripts, and lab manifests use temporary directories.
- Test cleanup closes database sessions and removes temporary resources.

## Test files

| File | What it verifies |
| --- | --- |
| `test_backend_workflows.py` | Password hashing, authentication, API request logging, controller/use-case/repository tracing, scan execution, timeout handling, project scope checks, and report response schemas. |
| `test_terminal_assistant.py` | Terminal sanitisation, secret redaction, target scope enforcement, Nmap command validation, evidence parsing, Ollama response handling, and transcript file following. |
| `test_terminal_workflow.py` | Login and project selection, scope setup, staged scans, findings, recommendations, report rendering, live command detection, QTerminal/Terminator splitting, and the gated Metasploitable 2 workflow. |
| `__init__.py` | Marks `tests` as an importable Python package so individual modules and test classes can be addressed by name. |

## Run every test

Open a terminal in the project root—the directory containing `Backend/`,
`tests/`, and `ptas.sh`—and run:

```bash
./test.sh
```

`test.sh` uses unittest discovery, so it automatically runs every current or
future file named `test_*.py` inside `tests/`. Before discovery, it runs
`generate-tests.py`, which scans the current `Backend/` tree and recreates three
structural test files:

- `test_generated_backend.py`
- `test_generated_terminal_assistant.py`
- `test_generated_terminal_workflow.py`

The generated files check that every discovered Python module imports and that
its top-level functions and classes exist. Adding or removing backend source is
therefore reflected the next time `./test.sh` runs. Generated files are ignored
by Git because they can always be recreated from the source tree.

The equivalent command without the helper script is:

```bash
./.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

The current suite should finish with output similar to:

```text
----------------------------------------------------------------------
Ran 78 tests

OK
```

The number will increase when new tests are added. The important result is the
final `OK`. A `FAILED` or `ERROR` result means at least one test needs attention.

## Run one test file

Backend workflow tests:

```bash
./.venv/bin/python -m unittest -v tests.test_backend_workflows
```

Terminal assistant tests:

```bash
./.venv/bin/python -m unittest -v tests.test_terminal_assistant
```

Terminal workflow tests:

```bash
./.venv/bin/python -m unittest -v tests.test_terminal_workflow
```

## Run one class or method

Run one test class:

```bash
./.venv/bin/python -m unittest -v \
  tests.test_backend_workflows.BackendWorkflowTests
```

Run one specific test method:

```bash
./.venv/bin/python -m unittest -v \
  tests.test_backend_workflows.BackendWorkflowTests.test_scan_timeout_returns_gateway_timeout_and_persists_the_error
```

Running one method is useful when debugging because it produces less output and
executes only the behavior currently being changed.

## Run after activating the virtual environment

The same tests can be run with the shorter `python` command after activation:

```bash
source .venv/bin/activate
python -m unittest discover -v
```

Leave the virtual environment afterward with:

```bash
deactivate
```

## Optional pytest command

The tests use Python's built-in `unittest` framework. If pytest is installed, it
can also discover and run them:

```bash
./.venv/bin/python -m pytest -q
```

Pytest is optional; the `unittest` commands above are the supported commands and
do not require installing another test framework.

## How a test is organised

Most tests follow Arrange, Act, Assert:

1. **Arrange** creates known records, input, mocks, or temporary files.
2. **Act** calls the function or workflow being tested.
3. **Assert** compares the returned value or side effect with the expected result.

Example:

```python
# Arrange: create a known password.
password = "safe-test-password"

# Act: hash it with the application helper.
hashed = hash_password(password)

# Assert: the correct password passes and a wrong password fails.
self.assertTrue(verify_password(password, hashed))
self.assertFalse(verify_password("wrong-password", hashed))
```

Mocks and test doubles are used only to control external dependencies. The PTAS
business function under test still runs normally.

## Understanding failures

A typical failure contains:

```text
FAIL: test_name (tests.test_module.TestClass.test_name)
AssertionError: expected value != actual value
```

Read it from the bottom upward:

1. The final line explains the difference.
2. The traceback identifies the failing assertion.
3. The test name describes the behavior that was expected.

An `ERROR` usually means the test raised an unexpected exception before reaching
its assertion. A `FAIL` normally means the code completed but returned the wrong
result.

## Troubleshooting

If Python reports that `Backend` or `tests` cannot be imported, confirm that the
command is being run from the project root:

```bash
pwd
```

If the virtual environment or dependencies are missing, run the Kali setup:

```bash
./kali-setup.sh
```

Then run the complete suite again. The API does not need to be started with
`./start.sh` before running unit tests.

## Adding a test

- Place the test in the file matching the feature being checked.
- Use a method name beginning with `test_` so discovery can find it.
- Keep inputs deterministic; do not depend on a live target or internet service.
- Use an in-memory database, mock, or temporary directory for external state.
- Include a short comment explaining the behavior being protected.
- Run the complete suite before committing the change.

The generator automatically supplies structural smoke tests, but it cannot infer
the correct business result from implementation code. Keep deliberate behavioral
tests for authentication, scope, failures, recommendations, and reports;
otherwise a generated test could repeat the same assumption as a faulty function.
