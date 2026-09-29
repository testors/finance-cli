"""Explicit offline effects/fault observations, never Android or IO execution."""
from dataclasses import dataclass

from .codeguard_flow import ObservedJavaException, java_substring
from .codeguard_rule import AnalysisLimit


@dataclass(frozen=True, repr=False)
class Effect:
    kind: str
    args: tuple = ()


class JavaFault(ObservedJavaException):
    """Observed or statically reconstructed Java Exception, not a Python error.

    Message/toString are needed for SDK wire compatibility, but never appear
    in str/repr/tracebacks. Synthetic tests may explicitly provide these.
    Pure adapters may reconstruct a fault from verified runtime bytecode;
    they must not use this class to disguise an AnalysisLimit/Python failure.
    """
    def __init__(self, kind, *, message, java_string, bases=()):
        super().__init__('observed_java_exception')
        self.kind, self.message, self.java_string = kind, message, java_string
        self.bases = tuple(bases)

    def is_instance(self, kind):
        return self.kind == kind or kind in self.bases


class LinkFault(Exception):
    """Observed UnsatisfiedLinkError, distinct from catch(Exception)."""
    def __init__(self, *, message=None):
        super().__init__('observed_unsatisfied_link_error')
        self.message = message


def observed_bool(value):
    if type(value) is not bool:
        raise AnalysisLimit('actual Java boolean observation required')
    return value


def java_length(value):
    if value is None:
        raise AnalysisLimit('null Java String needs original exception-text adapter')
    return len(value.encode('utf-16-le', 'surrogatepass')) // 2


def shortened_log(value, limit):
    length = java_length(value)
    if length > limit:
        value = java_substring(value, 0, limit//2) + '--' + java_substring(value, length-limit//2)
    return value.replace('#', '_')


def signed_long(value):
    if type(value) is not int:
        raise AnalysisLimit('observed Java clock value required')
    return (value + 2**63) % 2**64 - 2**63
