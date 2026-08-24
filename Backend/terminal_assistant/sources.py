"""Read new output from the transcript written by the student terminal."""

from pathlib import Path


class FollowFileSource:
    """Represent or coordinate FollowFileSource in the terminal guidance pipeline.

    The assistant analyzes evidence but never automatically executes its
    recommendations.
    """

    # Open a transcript follower that remembers its byte offset between dashboard reads.
    def __init__(self, path: Path, from_start: bool = False):
        if not path.exists() or not path.is_file():
            raise RuntimeError(f"Transcript file does not exist: {path}")
        self.path = path
        self.position = 0 if from_start else path.stat().st_size

    # Read only transcript bytes appended since the previous dashboard poll.
    def read_new(self) -> str:
        """Perform the read new step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """

        current_size = self.path.stat().st_size
        if current_size < self.position:
            self.position = 0
        with self.path.open("rb") as handle:
            handle.seek(self.position)
            content = handle.read()
            self.position = handle.tell()
        return content.decode("utf-8", errors="replace")
