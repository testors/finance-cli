"""HTTP API and static app. Requests only accept or read jobs; workers do the work.

Same-origin only: the Host header must name the configured public origin or
the loopback listener, state changes need the configured Origin and the CSRF
token, and responses never echo request values. Proxy headers are read only
from loopback peers and only for the client address.
"""
from contextlib import asynccontextmanager
from importlib.resources import files
import json
import re
import sqlite3

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from finance_cli.core import credential_refs
from . import access, capabilities, jobs, model
from .adapters.base import InputError
from .config import loopback
from .db import Database
from .dispatch import Dispatcher, start_with_secrets

API = '/api/v1'
JSON_LIMIT = 256 * 1024
CERTIFICATE_JOB_LIMIT = 12 * 1024 * 1024 + JSON_LIMIT
UPLOAD_LIMIT = 2 * 1024 * 1024 + 1024
CODE = re.compile(r'[a-z][a-z0-9_]{1,63}(:[a-z0-9_,]{1,120})?')
STATIC = {'index.html': 'text/html; charset=utf-8', 'app.css': 'text/css; charset=utf-8',
          'app.js': 'text/javascript; charset=utf-8', 'views.js': 'text/javascript; charset=utf-8',
          'api.js': 'text/javascript; charset=utf-8', 'ui.js': 'text/javascript; charset=utf-8',
          'certificates.js': 'text/javascript; charset=utf-8', 'corporate.js': 'text/javascript; charset=utf-8'}
PUBLIC_API = {(f'{API}/auth/state', 'GET'), (f'{API}/auth/enroll', 'POST')}
APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
           "frame-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
DOCUMENT_CSP = "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'self'"


class ApiError(Exception):
    def __init__(self, status, code, *, reasons=()):
        super().__init__(code)
        self.status, self.code = status, code
        self.reasons = reasons


def code_of(error, fallback='invalid_request'):
    text = str(error)
    return text if CODE.fullmatch(text) else fallback


def client_address(request):
    peer = request.client.host if request.client else None
    if peer and loopback(peer):
        forwarded = request.headers.get('x-forwarded-for')
        if forwarded:
            return forwarded.split(',')[-1].strip()[:64]
    return peer


def create_app(config, *, db=None, dispatcher=True, vaults=None):
    from .vaults import Vaults
    db = db or Database()
    worker = Dispatcher(db) if dispatcher else None
    vaults = vaults if vaults is not None else Vaults()

    @asynccontextmanager
    async def lifespan(app):
        with db.write() as con:
            model.restore_hana_accounts(con)
        if worker:
            worker.start()
        try:
            yield
        finally:
            if worker:
                worker.stop()

    app = FastAPI(title='Finance', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.config, app.state.db, app.state.dispatcher, app.state.vaults = config, db, worker, vaults

    def error(status, code, *, reasons=()):
        value = {'error': code}
        if reasons:
            value['reasons'] = list(reasons)
        return JSONResponse(value, status_code=status, headers={'Cache-Control': 'no-store'})

    @app.exception_handler(ApiError)
    async def api_error(request, exc):
        return error(exc.status, exc.code, reasons=exc.reasons)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return error(400, 'invalid_request')

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        return error(exc.status_code, 'not_found' if exc.status_code == 404 else 'invalid_request')

    @app.middleware('http')
    async def guard(request: Request, call_next):
        host = request.headers.get('host', '')
        if host not in config.allowed_hosts():
            return error(421, 'host_not_allowed')
        path, method = request.url.path, request.method
        length = request.headers.get('content-length')
        limit = UPLOAD_LIMIT if path == f'{API}/uploads' else \
            CERTIFICATE_JOB_LIMIT if path == f'{API}/jobs' and method == 'POST' else JSON_LIMIT
        if length is not None and (not length.isdigit() or int(length) > limit):
            return error(413, 'request_too_large')
        if request.headers.get('transfer-encoding'):
            # Bodies are only read with a declared, bounded length.
            return error(411, 'length_required')
        request.state.device = request.state.token = None
        if path.startswith(API + '/'):
            if method not in ('GET', 'HEAD') and request.headers.get('origin') not in config.allowed_origins():
                return error(403, 'origin_not_allowed')
            token = request.cookies.get(access.COOKIE)
            if token:
                with db.write() as con:
                    request.state.device = access.authenticate(con, config, token)
                if request.state.device:
                    request.state.token = token
            if (path, method) not in PUBLIC_API:
                if request.state.device is None:
                    return error(401, 'access_required')
                if method not in ('GET', 'HEAD') and request.headers.get('x-csrf-token') != access.csrf_token(token):
                    return error(403, 'csrf_token_invalid')
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers.setdefault('X-Frame-Options', 'DENY')
        if path.startswith(API + '/'):
            response.headers.setdefault('Cache-Control', 'no-store')
        return response

    async def body(request, limit=JSON_LIMIT):
        raw = await request.body()
        if len(raw) > limit:
            raise ApiError(413, 'request_too_large')
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except ValueError:
            raise ApiError(400, 'invalid_json') from None
        if not isinstance(value, dict):
            raise ApiError(400, 'invalid_json')
        return value

    def origin(request):
        return 'web:' + request.state.device['id']

    def run(function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except model.NotFound as exc:
            raise ApiError(404, code_of(exc, 'not_found')) from None
        except jobs.NotReady as exc:
            raise ApiError(409, code_of(exc, 'conflict'), reasons=exc.reasons) from None
        except model.Conflict as exc:
            raise ApiError(409, code_of(exc, 'conflict')) from None
        except (InputError, ValueError, KeyError, TypeError, AttributeError, sqlite3.InterfaceError,
                sqlite3.ProgrammingError) as exc:
            raise ApiError(400, code_of(exc) if isinstance(exc, ValueError) else 'invalid_request') from None

    # Static application ------------------------------------------------------

    def static(name):
        data = files('finance_cli.server').joinpath('static', name).read_bytes()
        headers = {'Content-Security-Policy': APP_CSP, 'Cache-Control': 'no-cache'}
        return Response(data, media_type=STATIC[name], headers=headers)

    @app.get('/')
    def index():
        return static('index.html')

    @app.get('/static/{name}')
    def static_file(name: str):
        if name not in STATIC or name == 'index.html':
            raise ApiError(404, 'not_found')
        return static(name)

    # Browser access ---------------------------------------------------------

    @app.get(API + '/auth/state')
    def auth_state(request: Request):
        device = request.state.device
        value = {'enrolled': device is not None, 'public_origin': config.public_origin, 'mode': config.mode}
        if device:
            value.update(device={'id': device['id'], 'name': device['name']},
                         csrf_token=access.csrf_token(request.state.token))
        return value

    @app.post(API + '/auth/enroll')
    async def auth_enroll(request: Request):
        value = await body(request)
        name = value.get('device_name')
        if name is not None and not isinstance(name, str):
            raise ApiError(400, 'invalid_device_name')
        with db.write() as con:
            device_id, token = access.enroll(con, config, value.get('code'), name, client_address(request))
        if device_id is None:
            raise ApiError(429 if token == 'enrollment_rate_limited' else 403, token)
        response = JSONResponse({'enrolled': True, 'device': {'id': device_id}, 'csrf_token': access.csrf_token(token)})
        response.set_cookie(access.COOKIE, token, max_age=config.absolute_days * 86400, path='/', secure=config.secure,
                            httponly=True, samesite='strict')
        return response

    @app.post(API + '/auth/logout')
    def auth_logout(request: Request):
        with db.write() as con:
            access.revoke(con, request.state.device['id'])
        response = JSONResponse({'logged_out': True})
        response.delete_cookie(access.COOKIE, path='/', secure=config.secure, httponly=True, samesite='strict')
        return response

    @app.get(API + '/auth/devices')
    def auth_devices(request: Request):
        with db.read() as con:
            return {'devices': access.devices(con, request.state.device['id'])}

    @app.delete(API + '/auth/devices/{device_id}')
    def auth_revoke(device_id: str):
        with db.write() as con:
            run(access.revoke, con, device_id)
        return {'revoked': True}

    # Settings and model -------------------------------------------------------

    @app.get(API + '/capabilities')
    def get_capabilities():
        return capabilities.global_capabilities()

    @app.get(API + '/profiles/{profile_id}/capabilities')
    def get_profile_capabilities(profile_id: str):
        with db.read() as con:
            return run(capabilities.profile_capabilities, con, profile_id)

    @app.get(API + '/certificates/options')
    def certificate_options():
        from finance_cli.services.hana import onesign_setup, onesign_signup_protocol as signup, store
        from .adapters.certificates import terms_digest
        from finance_cli.core import storage
        configured = []
        directory = store.root('settings')
        storage.no_symlinks(directory)
        if directory.is_dir():
            for path in sorted(directory.glob('*.json')):
                try:
                    value = onesign_setup.load(path.stem)
                    if 'service_profile' in value:
                        configured.append({'name': path.stem, 'version': value['version']})
                except (ValueError, OSError, KeyError, TypeError, AttributeError):
                    continue
        return {'joint': {'issuance': False, 'import': ['npki', 'pfx']},
                'financial': {'issuance': False, 'remote_management': False},
                'hana': {'issuance': True, 'settings': configured, 'verification': 'live_untested',
                         'carriers': [{'code': code, 'name': label, 'terms': signup.sms_terms(code),
                                       'terms_digest': terms_digest(signup.sms_terms(code))}
                                      for code, label in signup.CARRIERS.items()]}, 'network_used': False}

    @app.get(API + '/credentials')
    def get_credentials():
        rows = run(model.credentials)
        with db.read() as con:
            for row in rows:
                # Display information only; removal and renaming stay with the server's local CLI.
                row['in_use'] = credential_refs.scan_database(con, row['type'], row['ref'])
        return {'credentials': rows}

    @app.post(API + '/credentials/{kind}/{ref}/remove')
    async def remove_credential(kind: str, ref: str, request: Request):
        """Delete one stored credential that nothing references; the name must be typed to confirm."""
        value = await body(request)
        if set(value) - {'confirm'}:
            raise ApiError(400, 'input_fields_not_accepted')
        if kind not in ('joint', 'onesign'):
            raise ApiError(404, 'not_found')
        if value.get('confirm') != ref:
            raise ApiError(400, 'removal_confirmation_mismatch')

        def remove():
            credential_refs.guard(kind, ref)
            if kind == 'joint':
                from finance_cli.credentials.registry import Registry
                return Registry().remove(ref)
            from finance_cli.services.hana.onesign_state import remove_identity
            result = remove_identity(ref)
            vaults.lock(ref)  # Nothing to unlock any more.
            return result
        try:
            result = await run_in_threadpool(remove)
        except credential_refs.CredentialInUse as exc:
            return JSONResponse({'error': 'credential_in_use', 'references': exc.references}, status_code=409,
                                headers={'Cache-Control': 'no-store'})
        except BlockingIOError:
            raise ApiError(409, 'resource_busy') from None
        except ValueError as exc:
            raise ApiError(404 if str(exc).endswith('not_found') else 400, code_of(exc)) from None
        return {'removed': True, 'type': kind, 'ref': ref, 'network_used': False,
                'blob_removed': result.get('blob_removed') if kind == 'joint' else None}

    @app.post(API + '/credentials/{kind}/{ref}/rename')
    async def rename_credential(kind: str, ref: str, request: Request):
        """Rename one stored credential that nothing references; the key material is untouched."""
        value = await body(request)
        if set(value) - {'new_name'}:
            raise ApiError(400, 'input_fields_not_accepted')
        if kind not in ('joint', 'onesign'):
            raise ApiError(404, 'not_found')
        new_name = value.get('new_name')
        if not isinstance(new_name, str):
            raise ApiError(400, 'invalid_name')

        def rename():
            credential_refs.guard(kind, ref)
            if kind == 'joint':
                from finance_cli.credentials.registry import Registry
                return Registry().rename(ref, new_name)
            from finance_cli.services.hana.onesign_state import rename_identity
            result = rename_identity(ref, new_name)
            vaults.rename(ref, new_name)
            return result
        try:
            result = await run_in_threadpool(rename)
        except credential_refs.CredentialInUse as exc:
            return JSONResponse({'error': 'credential_in_use', 'references': exc.references}, status_code=409,
                                headers={'Cache-Control': 'no-store'})
        except BlockingIOError:
            raise ApiError(409, 'resource_busy') from None
        except ValueError as exc:
            code = code_of(exc)
            raise ApiError(404 if code.endswith('not_found') else 409 if code == 'credential_name_exists' else 400,
                           code) from None
        return {'renamed': True, 'type': kind, 'ref': result['name'], 'previous_ref': ref, 'network_used': False}

    # Saved identity cards ---------------------------------------------------
    # Listing reads the index only (name, kind, card issue date, saved time). Saving
    # goes through the idcard.add job so the photo and numbers stay in the worker pipe.

    @app.get(API + '/id-cards')
    def get_id_cards():
        from finance_cli.credentials.id_cards import IdCards
        return {'id_cards': run(IdCards().list), 'network_used': False}

    def id_card_change(function, *args):
        try:
            return function(*args)
        except BlockingIOError:
            raise ApiError(409, 'resource_busy') from None
        except ValueError as exc:
            code = code_of(exc)
            raise ApiError(404 if code.endswith('not_found') else 409 if code == 'id_card_name_exists' else 400,
                           code) from None

    @app.post(API + '/id-cards/{ref}/rename')
    async def rename_id_card(ref: str, request: Request):
        value = await body(request)
        if set(value) - {'new_name'}:
            raise ApiError(400, 'input_fields_not_accepted')
        if not isinstance(value.get('new_name'), str):
            raise ApiError(400, 'invalid_name')
        from finance_cli.credentials.id_cards import IdCards
        result = await run_in_threadpool(id_card_change, IdCards().rename, ref, value['new_name'])
        return {'renamed': True, 'ref': result['name'], 'previous_ref': ref, 'network_used': False}

    @app.post(API + '/id-cards/{ref}/remove')
    async def remove_id_card(ref: str, request: Request):
        """Delete one saved card without decrypting it; the name must be typed to confirm."""
        value = await body(request)
        if set(value) - {'confirm'}:
            raise ApiError(400, 'input_fields_not_accepted')
        if value.get('confirm') != ref:
            raise ApiError(400, 'removal_confirmation_mismatch')
        from finance_cli.credentials.id_cards import IdCards
        result = await run_in_threadpool(id_card_change, IdCards().remove, ref)
        return {'removed': True, 'ref': ref, 'blob_removed': result['blob_removed'], 'network_used': False}

    @app.get(API + '/logins')
    def get_logins():
        from . import session_activity
        with db.read() as con:
            rows = model.list_logins(con)
            for row in rows:
                row['readiness'] = capabilities.login_readiness(con, model.get_login(con, row['id'], raw=True))
                session = model.current_session(con, row['id'])
                # Display metadata only: no cookies, file locations or verdict payloads.
                row['session'] = None if session is None else {
                    'state': session['state'], 'created_at': session['created_at'], 'checked_at': session['checked_at']}
                if session is not None and row['institution'] == 'hana':
                    row['session'].update(session_activity.metadata(con, session))
            return {'logins': rows, 'server_time': session_activity.now()}

    @app.post(API + '/logins')
    async def post_login(request: Request):
        value = await body(request)
        allowed = {'institution', 'method', 'name', 'credential', 'channel', 'signing'}
        if set(value) - allowed:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.write() as con:
            return run(model.create_login, con, institution_name=value.get('institution'), method=value.get('method'),
                       name=value.get('name'), credential=value.get('credential'), channel=value.get('channel'),
                       signing=value.get('signing'))

    @app.get(API + '/corporate/options')
    def corporate_options():
        from finance_cli.services.hana_corporate import keypad
        from finance_cli.services.hana import store
        settings, reason = [], None
        for path in sorted(store.root('settings').glob('*.json')):
            try:
                keypad.load(path.stem)
                settings.append(path.stem)
            except (OSError, ValueError, KeyError, TypeError):
                continue
        try:
            selected, _ = keypad.resolve()
        except ValueError as error:
            selected, reason = None, code_of(error)
        return {'settings': settings, 'selected': selected, 'reason': reason, 'network_used': False}

    @app.patch(API + '/logins/{login_id}')
    async def patch_login(login_id: str, request: Request):
        value = await body(request)
        if set(value) - {'expected_revision', 'name', 'credential', 'signing', 'channel', 'disabled', 'registration'}:
            raise ApiError(400, 'input_fields_not_accepted')
        if 'registration' in value and set(value['registration'] or {}) - {'onesign_settings'}:
            raise ApiError(400, 'registration_is_server_managed')
        with db.write() as con:
            return run(model.update_login, con, login_id, **value)

    @app.post(API + '/logins/{login_id}/remove')
    async def remove_login(login_id: str, request: Request):
        value = await body(request)
        if set(value) - {'expected_revision'}:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.write() as con:
            result = run(model.remove_login, con, login_id, expected_revision=value.get('expected_revision'))
        files = result.pop('_files')
        removed, failed = 0, 0
        for relative in files:
            try:
                remove_private(relative)
                removed += 1
            except OSError:
                failed += 1  # The connection is gone; a leftover private file is reported, not fatal.
        from .registration import remove as remove_registration
        remove_registration(login_id)
        return {**result, 'session_files_removed': removed, 'session_files_not_removed': failed}

    @app.get(API + '/logins/{login_id}/auth-options')
    def get_auth_options(login_id: str):
        from .institutions import auth_options
        with db.read() as con:
            login = run(model.get_login, con, login_id)
        return auth_options(login['institution'], login['method'])

    @app.get(API + '/logins/{login_id}/sessions')
    def get_sessions(login_id: str):
        with db.read() as con:
            return run(model.list_sessions, con, login_id)

    @app.get(API + '/logins/{login_id}/targets')
    def get_targets(login_id: str):
        with db.read() as con:
            run(model.get_login, con, login_id)
            return {'targets': model.list_targets(con, login_id)}

    @app.post(API + '/logins/{login_id}/targets')
    async def post_target(login_id: str, request: Request):
        value = await body(request)
        if set(value) - {'job_id', 'candidate', 'name'}:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.write() as con:
            job = run(jobs.get, con, str(value.get('job_id')))
            return run(model.register_target, con, login_id, job, value.get('candidate'), value.get('name'))

    @app.get(API + '/targets')
    def all_targets():
        with db.read() as con:
            return {'targets': model.list_targets(con)}

    @app.patch(API + '/targets/{target_id}')
    async def patch_target(target_id: str, request: Request):
        value = await body(request)
        if set(value) - {'expected_revision', 'name', 'signing', 'disabled'}:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.write() as con:
            return run(model.update_target, con, target_id, **value)

    @app.get(API + '/profiles')
    def get_profiles():
        with db.read() as con:
            return {'profiles': model.list_profiles(con)}

    @app.post(API + '/profiles')
    async def post_profile(request: Request):
        value = await body(request)
        if set(value) - {'name', 'kind', 'target_ids'}:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.write() as con:
            return run(model.create_profile, con, name=value.get('name'), kind=value.get('kind'),
                       target_ids=value.get('target_ids') or [])

    @app.patch(API + '/profiles/{profile_id}')
    async def patch_profile(profile_id: str, request: Request):
        value = await body(request)
        if set(value) - {'name', 'kind', 'target_ids', 'disabled'}:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.write() as con:
            return run(model.update_profile, con, profile_id, **value)

    # Jobs -------------------------------------------------------------------

    def secrets_of(value, needed, vault=None, limits=None):
        provided = value.get('secrets') or {}
        if not isinstance(provided, dict) or set(provided) - set(needed) \
                or not all(isinstance(v, str) and 0 < len(v) <= (limits or {}).get(k, 1024) for k, v in provided.items()):
            raise ApiError(400, 'step_secrets_required' if needed else 'secrets_not_accepted')
        provided = dict(provided)
        remembered = vaults.get(vault) if vault and 'vault_passphrase' in needed else None
        if remembered and 'vault_passphrase' not in provided:
            # Unlocked on this server: the store passphrase comes from memory, not the browser.
            provided['vault_passphrase'] = remembered
        if set(provided) != set(needed):
            raise ApiError(400, 'step_secrets_required')
        return provided

    def onesign_store(con, login_id, *, target_id=None, parent_job_id=None, snapshot=None, transfer=False):
        """The OneSign store a job opens, from stored settings only (never from the browser)."""
        if not isinstance(login_id, str):
            return None
        login = con.execute('SELECT * FROM logins WHERE id=?', (login_id,)).fetchone()
        if login is None or login['method'] != 'onesign':
            return None
        signing = (snapshot or {}).get('signing')
        if signing is None and isinstance(parent_job_id, str):
            parent = con.execute('SELECT snapshot FROM jobs WHERE id=?', (parent_job_id,)).fetchone()
            signing = json.loads(parent['snapshot']).get('signing') if parent else None
        if signing is None and transfer:
            target = con.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone() \
                if isinstance(target_id, str) else None
            signing = model.signing_for(con, login, target, 'transfer_sign')
        if isinstance(signing, dict) and signing.get('type') == 'onesign':
            return signing.get('ref')
        return (json.loads(login['credential'] or 'null') or {}).get('ref')

    def start_secret_step(job, provided, *, on_busy):
        status = start_with_secrets(job['id'], job['step'], provided)
        if status == 'started':
            return
        # The worker can cross the idle deadline after API admission but before
        # asking for secrets. Keep its terminal record and return the real reason.
        with db.read() as con:
            current = jobs.get(con, job['id'])
        if json.loads(current['local']).get('stopped') == 'session_idle_expired':
            raise ApiError(409, 'session_idle_expired')
        on_busy(status)
        raise ApiError(409, 'resource_busy' if status == 'busy' else 'worker_not_started')

    @app.get(API + '/jobs')
    def get_jobs(profile_id: str = None, area: str = None, limit: int = 100):
        with db.read() as con:
            return {'jobs': jobs.listing(con, profile_id=profile_id, area=area, limit=limit)}

    @app.get(API + '/jobs/{job_id}')
    def get_job(job_id: str):
        with db.read() as con:
            return jobs.public(con, run(jobs.get, con, job_id))

    @app.post(API + '/jobs')
    async def post_job(request: Request):
        value = await body(request, CERTIFICATE_JOB_LIMIT)
        if set(value) - {'name', 'login_id', 'target_id', 'profile_id', 'input', 'secrets', 'idempotency_key',
                         'parent_job_id'}:
            raise ApiError(400, 'input_fields_not_accepted')
        adapter = jobs.registry.get(value.get('name'))
        if adapter is None:
            raise ApiError(404, 'job_name_not_registered')
        if len(await request.body()) > JSON_LIMIT and not getattr(adapter, 'secret_limits', None):
            raise ApiError(413, 'request_too_large')
        needed = adapter.steps[adapter.first_step].secrets
        with db.read() as con:
            store = onesign_store(con, value.get('login_id'), target_id=value.get('target_id'),
                                  parent_job_id=value.get('parent_job_id'), transfer=adapter.purpose == 'transfer_sign')
        from .adapters.certificates import OneSignIssuance
        if isinstance(adapter, OneSignIssuance):
            # Issuance precedes a login. Validate its explicit store and send approval
            # before retrieving the passphrase already unlocked in server memory.
            issuance = run(adapter.validate, value.get('input'))
            store = issuance['name'] if adapter.stage != 'init' else None
        provided = secrets_of(value, needed, store, getattr(adapter, 'secret_limits', None))
        job, created = run(jobs.submit, db, name=value['name'], origin=origin(request), login_id=value.get('login_id'),
                           target_id=value.get('target_id'), profile_id=value.get('profile_id'),
                           input=value.get('input'), idempotency_key=value.get('idempotency_key'),
                           parent_job_id=value.get('parent_job_id'))
        if created and needed:
            # Waiting for the worker's "ready" must not block other requests.
            await run_in_threadpool(start_secret_step, job, provided, on_busy=lambda status: jobs.cancel(
                db, job['id'], origin(request), 'resource_busy_secrets_not_sent' if status == 'busy'
                else 'worker_not_started_secrets_not_sent'))
        with db.read() as con:
            return JSONResponse(jobs.public(con, jobs.get(con, job['id'])), status_code=202 if created else 200)

    @app.post(API + '/jobs/{job_id}/confirm')
    async def confirm_job(job_id: str, request: Request):
        value = await body(request)
        if set(value) - {'confirmation', 'secrets'}:
            raise ApiError(400, 'input_fields_not_accepted')
        with db.read() as con:
            current = run(jobs.get, con, job_id)
        awaiting = json.loads(current['awaiting']) if current['awaiting'] else {}
        adapter = jobs.registry.get(current['name'])
        next_step = awaiting.get('next_step')
        needed = adapter.steps[next_step].secrets if next_step in getattr(adapter, 'steps', {}) else ()
        with db.read() as con:
            store = onesign_store(con, current['login_id'], snapshot=json.loads(current['snapshot']))
        provided = secrets_of(value, needed, store) if current['status'] == 'awaiting_input' else {}
        job, changed = run(jobs.accept_confirmation, db, job_id, value.get('confirmation'), origin(request))
        if changed and needed:
            await run_in_threadpool(start_secret_step, job, provided,
                                    on_busy=lambda status: jobs.revert_confirmation(db, job_id, status))
        with db.read() as con:
            return jobs.public(con, jobs.get(con, job_id))

    @app.get(API + '/jobs/{job_id}/corporate-ars')
    def corporate_ars(job_id: str):
        # The short telephone challenge comes from the private bank receipt only
        # while this step is awaiting input. It never enters job history or logs.
        from .adapters.hana_corporate import ars_challenge
        with db.read() as con:
            current = run(jobs.get, con, job_id)
            session = con.execute('SELECT name FROM sessions WHERE id=?', (current['session_id'],)).fetchone()
        return run(ars_challenge, current, session['name'] if session else None)

    @app.post(API + '/jobs/{job_id}/inputs')
    async def job_inputs(job_id: str, request: Request):
        await body(request)
        with db.read() as con:
            current = run(jobs.get, con, job_id)
        raise ApiError(409, 'job_not_awaiting_input' if current['status'] != 'awaiting_input'
                       else 'input_kind_not_supported')

    @app.post(API + '/jobs/{job_id}/cancel')
    async def cancel_job(job_id: str, request: Request):
        await body(request)
        run(jobs.cancel, db, job_id, origin(request))
        with db.read() as con:
            return jobs.public(con, jobs.get(con, job_id))

    # OneSign stores unlocked in this server's memory ------------------------

    @app.get(API + '/vaults')
    def get_vaults():
        names = [c['ref'] for c in run(model.credentials) if c['type'] == 'onesign']
        return {'vaults': [{'name': n, 'unlocked': vaults.unlocked(n)} for n in names], 'kept_in': 'server_memory'}

    @app.post(API + '/vaults/{name}/unlock')
    async def unlock_vault(name: str, request: Request):
        value = await body(request)
        if set(value) - {'passphrase'}:
            raise ApiError(400, 'input_fields_not_accepted')
        await run_in_threadpool(run, vaults.unlock, name, value.get('passphrase'))
        return {'name': name, 'unlocked': True, 'kept_in': 'server_memory'}

    @app.post(API + '/vaults/{name}/lock')
    async def lock_vault(name: str, request: Request):
        await body(request)
        vaults.lock(name)
        return {'name': name, 'unlocked': False}

    # Files ------------------------------------------------------------------

    @app.post(API + '/uploads')
    async def post_upload(request: Request, kind: str):
        from .uploads import store_upload
        data = await request.body()
        if len(data) > UPLOAD_LIMIT:
            raise ApiError(413, 'request_too_large')
        filename = request.headers.get('x-file-name')
        return run(store_upload, db, kind, data, origin(request), filename)

    @app.get(API + '/artifacts')
    def list_artifacts(kind: str = None, profile_id: str = None):
        from .artifacts import listing
        with db.read() as con:
            return {'artifacts': run(listing, con, kind=kind, profile_id=profile_id)}

    @app.get(API + '/artifacts/{artifact_id}')
    def get_artifact(artifact_id: str, disposition: str = 'attachment'):
        from .artifacts import read_artifact
        row, data = run(read_artifact, db, artifact_id)
        headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
        if row['media_type'].startswith('text/html'):
            # Never runs with the app's origin: a sandboxed, script-less document.
            headers['Content-Security-Policy'] = DOCUMENT_CSP
            if disposition == 'inline':
                headers['X-Frame-Options'] = 'SAMEORIGIN'
        if disposition != 'inline' or not row['media_type'].startswith('text/html'):
            headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{quote_name(row['filename'])}"
        return Response(data, media_type=row['media_type'], headers=headers)

    return app


def remove_private(relative):
    """Delete one session file or web-created session directory inside the private stores."""
    import shutil
    from finance_cli.core import storage
    from finance_cli.core.paths import data_home
    base = data_home().absolute()
    path = storage.no_symlinks(base / relative)
    allowed = (base / 'server' / 'sessions', base / 'hana' / 'sessions', base / 'hana-corporate' / 'sessions', base / 'server' / 'jobs')
    if not any(path.is_relative_to(root) and path != root for root in allowed):
        raise OSError('outside_session_store')
    if path.is_relative_to(base / 'server' / 'jobs') and (path.is_dir() or path.name != 'result.json'):
        raise OSError('only_session_copies_in_job_records')
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def quote_name(name):
    from urllib.parse import quote
    return quote(name, safe='')
