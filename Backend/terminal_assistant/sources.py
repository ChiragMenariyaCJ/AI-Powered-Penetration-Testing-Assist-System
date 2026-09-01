
# This file handles sources.
from pathlib import Path


# Handle the follow file source.
class FollowFileSource:

    # Set up this object.
    def __init__(self, path: Path, from_start: bool = False):
        if not path.exists() or not path.is_file():
            raise RuntimeError(f"Transcript file does not exist: {path}")
        self.path = path
        self.position = 0 if from_start else path.stat().st_size

    # Read new.
    def read_new(self) -> str:

        current_size = self.path.stat().st_size
        if current_size < self.position:
            self.position = 0
        with self.path.open("rb") as handle:
            handle.seek(self.position)
            content = handle.read()
            self.position = handle.tell()
        return content.decode("utf-8", errors="replace")
