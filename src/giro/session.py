"""Explicit session activity through one encrypted server-time query."""
from datetime import datetime, timezone
import uuid

from finance_cli.core import storage
from .client import AuthenticatedClient
from .errors import GiroError
from .query_flow import response_report
from .session_store import SessionStore


def extend(*, send=False, store=None):
    result = {'operation': 'session-extend', 'method': 'encrypted-time-query', 'endpoint': 'auth.datetime',
              'network_used': False, 'automatic_login': False, 'automatic_retry': False,
              'request_accepted': None, 'login_extension_accepted': None, 'extension_effect': 'unverified',
              'session_ended': False, 'server_expires_at': None, 'session_current_validity': 'unverified',
              'app_success': None, 'service_decision': 'unobserved', 'processing_issues': []}
    if not send:
        return dict(result, plan_only=True, maximum_requests=1)
    store = store if store is not None else SessionStore()
    directory = None
    try:
        with store.use() as (session, issues):
            result['session_processing_issues'] = issues
            client = AuthenticatedClient(session)
            client.require_active()
            parent = storage.directory(store.root / 'session-operations')
            directory = parent / uuid.uuid4().hex
            directory.mkdir(mode=0o700)
            result['operation_id'] = directory.name
            storage.write_new(directory / 'attempt.json', b'{"endpoint":"auth.datetime","automatic_retry":false}\n')
            result['network_used'] = True
            response = client.query('auth.datetime', {}, send=True)
            result.update(response_report(response), request_accepted=response.app_success if response.origin == 'response' else None,
                          session_ended=response.clear_session, events=list(client.events),
                          observed_at=datetime.now(timezone.utc).isoformat())
            if response.clear_session:
                result['session_current_validity'] = 'ended'
    except (Exception, KeyboardInterrupt) as exc:
        result['error'] = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'session_extension_processing_incomplete'
        result['processing_issues'].append(result['error'])
        # No external exception text, session contents, or implicit retry.
        if isinstance(exc, GiroError) and not result['network_used']:
            result['error'] = 'giro_session_unavailable'
    finally:
        if directory is not None:
            try:
                storage.atomic_json(directory / 'outcome.json', result)
            except Exception:
                result['processing_issues'].append('outcome_storage_failed')
    return result
