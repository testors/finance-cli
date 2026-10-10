"""Local web idle policy for institution sessions; never changes an institution's session verdict."""
from .db import now

IDLE_SECONDS = 600
# The longest idle gap each service was seen to keep a session through (live trials, 2026-10-10):
# Giro kept 290 seconds and ended 315; Hana personal and corporate kept 590 and ended 620;
# Hometax kept 1,790 and no longer knew the login after 1,830.
SERVICE_IDLE_SECONDS = {'giro': 290, 'hana': 590, 'hana_corporate': 590, 'hometax': 1790}
EXPIRED = 'session_idle_expired'
# A session of these services counts as logged out after its idle limit without a request, unless
# it is extended. Hana personal requests are observed one by one at the HTTP boundary; the other
# services have no such observer and count a job's request reservation as their activity.
SERVICES = ('hana', 'hana_corporate', 'giro', 'hometax')
OBSERVED = ('hana',)


def metadata(con, session, service, at=None):
    row = con.execute('SELECT last_request_at FROM session_activity WHERE session_id=?',
                      (session['id'],)).fetchone()
    # Older sessions have no HTTP timestamp. Do not give them a fresh lifetime
    # on deployment or restart; their recorded creation time is the fallback.
    last = row['last_request_at'] if row else session['created_at']
    limit = SERVICE_IDLE_SECONDS.get(service, IDLE_SECONDS)
    expires = last + limit
    return {'last_request_at': last, 'idle_seconds': limit, 'idle_expires_at': expires,
            'idle_expired': (now() if at is None else at) >= expires}


def refusal(con, adapter, session, step=None):
    if adapter.service in SERVICES and adapter.uses_session and session is not None \
            and adapter.steps[step or adapter.first_step].sends \
            and metadata(con, session, adapter.service)['idle_expired']:
        return EXPIRED
    return None


def record(con, session_id, at):
    con.execute('INSERT INTO session_activity(session_id, last_request_at) VALUES (?,?) '
                'ON CONFLICT(session_id) DO UPDATE SET last_request_at=excluded.last_request_at', (session_id, at))
