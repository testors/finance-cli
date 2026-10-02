"""Immutable file summaries for a declared, precomputed content backend.

These are content digests, never a security verdict or a server token. This
backend represents complete reads of immutable bytes. Partial reads, changing
files and native IO failures still need the byte/observation backend. Process,
package and policy checks are performed separately on their explicit inputs.
"""
from dataclasses import dataclass
import hashlib

from .codeguard_rule import AnalysisLimit


@dataclass(frozen=True, repr=False)
class FileDigests:
    size: int
    sha256: bytes
    md5: bytes

    def __post_init__(self):
        if (type(self.size) is not int or not 0 <= self.size < 2**31
                or type(self.sha256) is not bytes or len(self.sha256) != 32
                or type(self.md5) is not bytes or len(self.md5) != 16):
            raise AnalysisLimit('complete immutable file digest metadata required')

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes:
            raise AnalysisLimit('immutable file bytes required for compilation')
        return cls(len(data), hashlib.sha256(data).digest(), hashlib.md5(data).digest())


@dataclass(repr=False, eq=False)
class DigestStream:
    owner: object
    data: FileDigests
    position: int = 0
    eof: bool = False
    closed: bool = False


@dataclass(frozen=True, repr=False)
class DigestRead:
    """Explicit complete-read representation; not a claimed native read log."""
    content: FileDigests

    def __post_init__(self):
        if not isinstance(self.content, FileDigests):
            raise AnalysisLimit('complete immutable file digests required')
