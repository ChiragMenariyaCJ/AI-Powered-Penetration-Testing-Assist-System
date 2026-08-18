from pathlib import Path
import shutil
import subprocess


def new_snapshot_text(previous: str, current: str) -> str:
    """Return the appended portion of a rolling terminal snapshot."""
    if not previous:
        return current
    if current.startswith(previous):
        return current[len(previous):]

    previous_lines = previous.splitlines(keepends=True)
    current_lines = current.splitlines(keepends=True)
    max_overlap = min(len(previous_lines), len(current_lines))
    for overlap in range(max_overlap, 0, -1):
        if previous_lines[-overlap:] == current_lines[:overlap]:
            return "".join(current_lines[overlap:])
    return current


class TmuxPaneSource:
    def __init__(self, pane: str, history_lines: int = 250):
        if not shutil.which("tmux"):
            raise RuntimeError("tmux is not installed or is not on PATH")
        self.pane = pane
        self.history_lines = history_lines
        self.previous = self._capture()

    def _capture(self) -> str:
        result = subprocess.run(
            [
                "tmux",
                "capture-pane",
                "-p",
                "-J",
                "-S",
                f"-{self.history_lines}",
                "-t",
                self.pane,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or "unknown tmux error"
            raise RuntimeError(f"Could not capture pane {self.pane}: {error}")
        return result.stdout

    def read_new(self) -> str:
        current = self._capture()
        new_text = new_snapshot_text(self.previous, current)
        self.previous = current
        return new_text


class FollowFileSource:
    def __init__(self, path: Path, from_start: bool = False):
        if not path.exists() or not path.is_file():
            raise RuntimeError(f"Transcript file does not exist: {path}")
        self.path = path
        self.position = 0 if from_start else path.stat().st_size

    def read_new(self) -> str:
        current_size = self.path.stat().st_size
        if current_size < self.position:
            self.position = 0
        with self.path.open("rb") as handle:
            handle.seek(self.position)
            content = handle.read()
            self.position = handle.tell()
        return content.decode("utf-8", errors="replace")
