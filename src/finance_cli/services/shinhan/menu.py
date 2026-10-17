"""Private menu loading, ordered recovery, and native program cross-check."""
import json
import urllib.error
import urllib.request

from finance_cli.core import storage
from . import menu_protocol as protocol, setup, transport
from .enrollment import Pending

ACTIVE = 'menu-active.json'
BACKUP = 'menu-backup.json'
TEMP = 'menu-download.json'
DEFAULT = 'menu_program_nss_default.json'


def get_file(filename):
    # This resource uses neither the banking cookie nor the certificate jar.
    request = urllib.request.Request('https://nssol.shinhan.com/images/menu/'+filename,
                                     headers={'Accept-Encoding': 'gzip'})
    try:
        response = urllib.request.urlopen(request, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, ValueError):
        return transport.Reply(error='menu_transport_error')
    with response:
        body = response.read(transport.LIMIT+1)
        reply = transport.Reply(response.status, list(response.headers.items()), body)
        if len(body) > transport.LIMIT:
            reply.error, reply.body = 'menu_response_too_large', b''
        elif response.headers.get('Content-Encoding') == 'gzip':
            import gzip
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                reply.body = stream.read(transport.LIMIT+1)
            if len(reply.body) > transport.LIMIT:
                reply.error, reply.body = 'menu_response_too_large', b''
        return reply


class Store:
    def __init__(self, settings, state, report, run):
        self.settings, self.state, self.report, self.run = settings, state, report, run
        self.folder = setup.root()
        self.queue = []
        self.value = (state.get('menu') or {}).get('value')
        self.events = report.setdefault('menu', {'events': []})['events']

    def warning(self, code):
        self.report.setdefault('warnings', []).append(code)
        self.report['local_status'] = 'incomplete'

    def delete(self, name):
        try:
            (self.folder/name).unlink(missing_ok=True)
        except OSError:
            self.warning('menu_file_delete_error')

    def copy(self, source, destination):
        # File-copy errors are consumed by the native loader after deletion.
        self.delete(destination)
        try:
            raw = storage.read(self.folder/source, limit=transport.LIMIT)
            storage.write_new(self.folder/destination, raw)
        except Exception:
            self.delete(destination)
            self.warning('menu_file_copy_error')

    def asset(self):
        self.state['menu_refresh_needed'] = True
        self.events.append({'action': 'copy_default'})
        try:
            value = self.settings['menu']
            storage.atomic_json(self.folder/ACTIVE, value)
        except Exception:
            self.delete(ACTIVE)
            self.warning('menu_default_copy_error')

    def direct(self):
        try:
            return protocol.decode(storage.read(self.folder/ACTIVE, limit=transport.LIMIT).decode('utf-8', errors='replace'))
        except Exception:
            return protocol.decode(json.dumps(self.settings['menu']))

    def before_start(self):
        self.state.pop('menu', None)
        self.value = None
        if self.state.get('menu_refresh_needed') is True:
            self.state['menu_refresh_needed'] = False
            self.delete(ACTIVE)
            self.events.append({'action': 'clear_for_refresh'})
        try:
            return self.direct()['VERSION']
        except Exception:
            # Older installations can still start before their menu is provisioned.
            return self.settings['menu_version']

    def parse(self, name, source):
        event = {'action': 'parse', 'source': source, 'result': 'unknown'}
        self.events.append(event)
        try:
            value = protocol.decode(storage.read(self.folder/name, limit=transport.LIMIT).decode('utf-8', errors='replace'))
            self.value = value
            self.state['menu'] = {'value': value, 'source': source, 'loaded': True}
            if name != ACTIVE:
                self.copy(name, ACTIVE)
            event['result'] = 'success'
            self.queue.clear()
        except Exception:
            event['result'] = 'error'
            self.delete(name)
            self.asset()
            self.poll()
        # parsingMenuFile's Result is consumed by its Unit-returning wrapper.

    def download(self, filename, source):
        event = {'action': 'download', 'source': source, 'result': 'unknown'}
        self.events.append(event)
        self.report['network_used'] = True
        # Diagnostic IO must not turn a menu GET into a fallback request.
        try:
            storage.atomic_json(self.run/'report.json', self.report)
        except Exception:
            self.warning('menu_report_save_error')
        try:
            reply = get_file(filename)
            event['http_status'] = reply.status
            if reply.error or reply.status != 200:
                event['error'] = reply.error or 'menu_http_status_error'
                raise ValueError('menu_download_unavailable')
            self.delete(TEMP)
            storage.write_new(self.folder/TEMP, reply.body)
            self.parse(TEMP, source)
        except Exception:
            event['result'] = 'error'
            self.poll()
            return False
        event['result'] = 'success'
        self.queue.clear()
        self.copy(TEMP, BACKUP)
        return True

    def poll(self):
        if not self.queue:
            return
        source = self.queue.pop(0)
        self.state['menu_refresh_needed'] = True
        if source == 'server_default':
            self.download(DEFAULT, source)
        else:
            self.parse(BACKUP if source == 'backup' else ACTIVE, source)

    def load(self, intro):
        if 'menu' not in self.settings:
            self.report['menu']['status'] = 'settings_refresh_required'
            return
        if intro.get('menuDownlYnS1') == 'Y':
            if not self.download(transport.primitive(intro.get('menuFileNmS100')), 'server'):
                self.queue.extend(('server_default', 'backup', 'default'))
                self.poll()
        else:
            self.delete(TEMP)
            if not (self.folder/ACTIVE).exists():
                self.asset()
            self.parse(ACTIVE, 'local')
        if self.value is None:
            # Local program lookup reads the active file directly when its map
            # is empty, including the default copied after a parsing failure.
            self.value = self.direct()
            self.state['menu'] = {'value': self.value, 'source': 'local', 'loaded': True}
        self.report['menu'].update(status='available', source=self.state['menu']['source'])


def resolve(exchange, identity):
    if 'menu' not in exchange.settings:
        raise Pending('loan_menu_settings_refresh_required')
    loader = Store(exchange.settings, exchange.state, exchange.report, exchange.run)
    if loader.value is None:
        loader.load(exchange.state.get('intro') or {})
    exchange.report['menu'].update(status='available', source=exchange.state['menu']['source'])
    if not loader.value['PROGRAM_LIST']:
        loader.value['PROGRAM_LIST'] = loader.direct()['PROGRAM_LIST']
    found = protocol.local(loader.value, identity)
    if found is None and not loader.value['ASIS_PRID_MAP']:
        loader.value['ASIS_PRID_MAP'] = loader.direct()['ASIS_PRID_MAP']
        found = protocol.local(loader.value, identity)
    if len(identity.encode('utf-16-le', errors='surrogatepass')) // 2 > 20:
        raise Pending('loan_destination_unavailable')
    if found is not None and found['PR_ID']:
        return found
    step, document = exchange.bank('loan_program_lookup', 'RSMCM9000H06', {'prId': identity},
        path=transport.ENDPOINT+'/', response_parser=protocol.parse_reply)
    exchange.report['bank_result'] = step['bank_result']
    exchange.report['program_lookup_result'] = step['bank_result']
    if step['processing_status'] != 'complete':
        raise Pending('loan_program_lookup_unverified')
    body = (document or {}).get('dataBody')
    if step['bank_result'] != 'success' or body is None or not body['prId']:
        raise Pending('loan_destination_unavailable')
    return protocol.remote(body)
