"""Adapter contract: allowlisted output, secret delivery and verdict preservation.

An adapter connects one existing business function or command to a web job.
It declares its steps, the secrets each step needs, the locks it must hold and
the fields that may leave the worker. The institution's own verdict fields are
kept verbatim in ``service_verdict``; ``outcome`` is only a derived summary.
"""
from dataclasses import dataclass, field
from datetime import date
import re

OUTCOMES = ('not_started', 'success', 'partial_success', 'rejected', 'unknown')


class InputError(ValueError):
    """The request input is not acceptable; nothing was sent."""


class Stop(Exception):
    """A step stops before or during work; the reason is recorded, never retried."""

    def __init__(self, code, *, sent=False, detail=None):
        super().__init__(code)
        self.code, self.sent, self.detail = code, sent, detail or {}


@dataclass(frozen=True)
class Step:
    name: str
    secrets: tuple = ()
    sends: bool = True
    next_on_success: str = None
    expires_seconds: int = None


@dataclass
class StepResult:
    service_verdict: dict = None
    result: dict = None
    outcome: str = 'unknown'
    local: dict = field(default_factory=dict)
    reconciliation: dict = None
    awaiting: dict = None
    confirmed_target: dict = None
    artifacts: list = field(default_factory=list)
    observed: bool = True

    def __post_init__(self):
        if self.outcome not in OUTCOMES:
            raise ValueError('invalid_outcome')


class Adapter:
    name = None
    title = None
    area = None
    service = None
    capability = None
    verification = None
    requires_login = True
    requires_target = False
    uses_session = False
    accepts_stale_session = False
    accepts_consumed_session = False
    session_from_parent = False
    purpose = None
    confirmation = False
    steps = {'run': Step('run')}
    first_step = 'run'
    input_masks = ()

    def validate(self, value, login=None):
        if value not in (None, {}):
            raise InputError('input_not_accepted')
        return {}

    def ready(self, login):
        """Refuse a login this job cannot use (method, registration)."""

    def accepts_session(self, session):
        return session is not None and (session['state'] == 'usable'
            or self.accepts_stale_session and session['state'] == 'stale'
            or self.accepts_consumed_session and session['state'] == 'consumed')

    def masked_input(self, value):
        return mask_fields(value, self.input_masks)

    def resources(self, ctx, step):
        return []

    def run(self, ctx, step):
        raise NotImplementedError

    def describe(self):
        return {'name': self.name, 'title': self.title, 'area': self.area, 'service': self.service,
                'requires_login': self.requires_login, 'requires_target': self.requires_target,
                'requires_confirmation': self.confirmation,
                'requires_input': sorted({s for step in self.steps.values() for s in step.secrets})}


# Allowlist helpers -------------------------------------------------------

def pick(value, keys):
    """Copy only allowlisted keys; unknown fields are excluded by default."""
    if not isinstance(value, dict):
        return None
    return {k: value[k] for k in keys if k in value}


def pick_rows(rows, keys, limit=2000):
    if not isinstance(rows, list):
        return None
    return [pick(r, keys) if isinstance(r, dict) else None for r in rows[:limit]]


def scalar(value):
    return value if isinstance(value, (str, int, float, bool)) or value is None else None


def mask_account(value):
    text = re.sub(r'\D', '', str(value or ''))
    return ('•' * max(len(text) - 4, 0) + text[-4:]) if text else None


def mask_fields(value, keys):
    if not isinstance(value, dict):
        return value
    return {k: (mask_account(v) if k in keys else v) for k, v in value.items()}


# Login extension -----------------------------------------------------------

# What a login extension job may report. Each institution sends its own request and keeps its
# own verdict; a field its service function does not state stays absent.
EXTENSION_FIELDS = ('request_accepted', 'login_extension_accepted', 'extension_effect', 'session_ended',
                    'native_client_timer_reset_ms', 'server_expires_at', 'session_current_validity')


def extension_result(ctx, value, *extra, mark_ended=True):
    """The allowlisted scalar result of a login extension job.

    A session the institution reported as ended is marked expired, so it is neither used nor
    extended again. Pass ``mark_ended=False`` where the adapter's own flow already records that.
    """
    if not isinstance(value, dict):
        return None
    if mark_ended and value.get('session_ended') is True:
        ctx.mark_session(ctx.session['id'], 'expired', 'institution_session_ended')
    return {key: scalar(value[key]) for key in EXTENSION_FIELDS + extra if key in value}


# Input helpers ------------------------------------------------------------

def dict_input(value, allowed, required=()):
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise InputError('input_fields_not_accepted')
    missing = [k for k in required if value.get(k) in (None, '')]
    if missing:
        raise InputError('input_required:' + ','.join(missing))
    return value


def iso_date(value, name):
    if value in (None, ''):
        return None
    try:
        return date.fromisoformat(value).isoformat() if isinstance(value, str) and len(value) == 10 else _bad(name)
    except ValueError:
        return _bad(name)


def _bad(name):
    raise InputError('invalid_' + name)


def choice(value, name, options):
    if value in (None, ''):
        return None
    if value not in options:
        raise InputError('invalid_' + name)
    return value


def bounded_int(value, name, low, high):
    if value in (None, ''):
        return None
    if type(value) is not int or not low <= value <= high:
        raise InputError('invalid_' + name)
    return value


def text(value, name, limit=100, pattern=None):
    if value in (None, ''):
        return None
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise InputError('invalid_' + name)
    if pattern and re.fullmatch(pattern, value) is None:
        raise InputError('invalid_' + name)
    return value
