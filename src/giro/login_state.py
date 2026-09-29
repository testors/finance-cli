"""In-memory replay of observed LoginInfo mutations, not an authenticated client.

No SDK execution, requests, credential storage, device registration, notifications
or actual timers. QueryClient's transport result is preserved separately from UI
callback exceptions and unsupported cases.
"""
from copy import deepcopy
from dataclasses import dataclass, field

from .compat import _read_model, loads, string_value
from .errors import GiroError
from .json_reader import JsonNumber, JsonObject
from .response import Received

STRING_FIELDS = tuple('billPushRegDatetime billPushYn certLoginYn currentDateTime '
                      'defaultLoginType demandOnlyYn deviceRegYn fidoCertFailCo fidoDelReqMsg '
                      'fidoLoginYn finCertLoginYn hasMultipleAccounts memberType paypinChangeDate '
                      'paypinErrorCount pinLoginYn pushId saupNo'.split())
BOOLEAN_FIELDS = tuple('isCertLogin isDeviceReg isFidoLogin isFinCertLogin isLogin isPinLogin'.split())
SPECIAL_FIELDS = ('currentLoginType', 'sessionInfo', 'sessionKey', 'loginCertificateInfo')
DEVICE_FLAGS = (('deviceRegYn', 'isDeviceReg'), ('certLoginYn', 'isCertLogin'),
                ('pinLoginYn', 'isPinLogin'), ('fidoLoginYn', 'isFidoLogin'),
                ('finCertLoginYn', 'isFinCertLogin'))
# LoginInfo.refresh guard/getter/setter triples in call order.
REFRESH_FIELDS = tuple((name, name, name) for name in (
    'pushId', 'billPushYn', 'billPushRegDatetime', 'paypinChangeDate', 'paypinErrorCount',
    'hasMultipleAccounts', 'deviceRegYn')) + tuple(
        (name, 'deviceRegYn', name) for name in
        ('certLoginYn', 'pinLoginYn', 'fidoLoginYn', 'finCertLoginYn')) + (
    ('defaultLoginType', 'defaultLoginType', 'defaultLoginType'),
    ('memberType', 'memberType', 'defaultLoginType'),
    ('demandOnlyYn', 'demandOnlyYn', 'demandOnlyYn'))


class StateAnalysisLimit(ValueError):
    """A secondary model path is not fully modeled; not an app failure."""


def _initial_values():
    return dict({name: None for name in STRING_FIELDS + SPECIAL_FIELDS},
                **{name: False for name in BOOLEAN_FIELDS}, currentLoginType='PIN')


def parse_login_info(text):
    """Second Gson pass, including known unused fields and duplicate ordering.

    Non-null CertificateInfo/nonempty sessionKey paths remain explicitly
    unmodeled, not ignored or rejected as if the server had failed.
    """
    value = loads(text) if text is not None else None
    if value is None:
        return None
    if not isinstance(value, dict):
        raise GiroError('LoginInfo object expected')
    result = _initial_values()
    for name, item in value.pairs if isinstance(value, JsonObject) else value.items():
        if name not in result:
            continue
        if item is None:
            if name not in BOOLEAN_FIELDS:
                result[name] = None
        elif name in STRING_FIELDS:
            result[name] = string_value(item)
        elif name in BOOLEAN_FIELDS:
            if isinstance(item, bool):
                result[name] = item
            elif isinstance(item, str) and not isinstance(item, JsonNumber):
                result[name] = item.lower() == 'true'
            else:
                raise GiroError('LoginInfo Boolean adapter cannot read token')
        elif name == 'currentLoginType':
            # EnumAdapter.nextString accepts numbers but not boolean values.
            if isinstance(item, (dict, list, bool)):
                raise GiroError('LoginInfo enum adapter cannot read token')
            result[name] = item if item in ('PIN', 'CERT', 'FIDO', 'FINCERT') else None
        elif name == 'sessionInfo':
            result[name] = _read_model(item, 'kr/or/giro/android/model/SessionInfo')
        elif name == 'sessionKey':
            if not isinstance(item, list):
                raise GiroError('LoginInfo array adapter cannot read token')
            if item:
                raise StateAnalysisLimit('secondary LoginInfo byte-array elements not modeled')
            result[name] = []
        else:
            raise StateAnalysisLimit('secondary LoginInfo certificate object not modeled')
    return result


@dataclass
class LoginState:
    values: dict = field(default_factory=_initial_values, repr=False)
    favorites_initialized: bool = False
    favorite_context: tuple | None = field(default=None, repr=False)
    timer_refresh_events: int = 0
    timer_start_events: int = 0

    @property
    def is_login(self):
        return bool(self.values.get('isLogin')) and self.values.get('sessionInfo') is not None

    def logout(self):
        # Not a cookie/SEED-key wipe. Do not erase unrelated retained metadata.
        self.values.update(sessionInfo=None, isLogin=False, loginCertificateInfo=None)

    def change_favorite_context(self):
        session = self.values.get('sessionInfo') or {}
        self.favorite_context = tuple(session.get(k) if session.get(k) is not None else '0'
                                      for k in ('userType', 'userId'))

    def refresh(self, metadata):
        for guard, source, target in REFRESH_FIELDS:
            if metadata.get(guard) is not None:
                self.values[target] = metadata.get(source)
        if self.favorites_initialized:
            self.change_favorite_context()
        session = metadata.get('sessionInfo')
        if session is not None:
            user_type = session.get('userType')
            self.values['memberType'] = user_type if user_type in ('1', '2') else '0'

    def device_status_success(self, query):
        # IntroPresenter$3 uses Boolean setters, unlike LoginInfo.refresh's
        # string setters. Exact "Y" only; null/unknown values become N/false.
        for source, target in DEVICE_FLAGS:
            enabled = query.get(source) == 'Y'
            self.values[target] = enabled
            self.values[source] = 'Y' if enabled else 'N'
        if query.get('memberType') == '1':
            self.values['saupNo'] = query.get('saupNo')
        # setDefaultLogin(enum) is immediately overwritten by this raw setter,
        # including null/unrecognized values. currentLoginType is NOT changed.
        self.values['defaultLoginType'] = query.get('defaultLoginType')
        self.favorites_initialized = True
        self.change_favorite_context()


@dataclass(frozen=True)
class StateReplay:
    transport: Received
    state: LoginState = field(repr=False)
    callback: str
    ui_status: str
    events: tuple[str, ...]
    issues: tuple[str, ...] = ()


def replay(name, received, state=None, *, listener_present=True):
    """Replay worker-thread -> UI -> device-status/PIN/datetime callbacks.

    Returns a COPY of the prior in-memory state. transport.app_success/code are
    not changed by a UI null dereference or missing analysis. For other API
    presenters, only common QueryClient/LoginInfo behavior is replayed.
    """
    state = deepcopy(state) if state is not None else LoginState()
    events = []
    issues = list(received.issues)

    def result(callback, status):
        return StateReplay(received, state, callback, status, tuple(events), tuple(issues))

    if received.origin == 'transport_io':
        if listener_present:
            events.append('callback.failure')
        return result('failure' if listener_present else 'none', 'completed')
    if received.session_update is not None:
        state.values['sessionInfo'] = deepcopy(received.session_update)
        events.append('session.update')
    state.timer_refresh_events += 1
    events.append('timer.refresh')
    if not listener_present:
        return result('none', 'listener_absent')
    if name == 'auth.pin' and received.query_source != 'none':
        events.append('login_info.deserialize')
        try:
            metadata = parse_login_info(received.response_text)
        except StateAnalysisLimit:
            issues.append('login_info_secondary_model_unmodeled')
            return result('none', 'unmodeled')
        except GiroError:
            # JsonUtil.deserialize catches JsonSyntaxException and returns null;
            # refresh immediately calls toString() on it outside the IO catch.
            metadata = None
        if metadata is None:
            events.append('login_info.refresh.null_exception')
            return result('none', 'ui_exception')
        state.refresh(metadata)
        events.append('login_info.refresh')
    if received.clear_session:
        state.logout()
        events.extend(('login.logout', 'callback.disconnected_session'))
        return result('disconnected_session', 'completed')
    events.append('callback.' + received.callback)
    if not received.app_success:
        return result(received.callback, 'completed')
    if name == 'auth.pin':
        if received.query.get('sessionInfo') is None:
            # Presenter logs getSessionInfo().toString() BEFORE setting login.
            events.append('pin_success.session_null_exception')
            return result('success', 'ui_exception')
        state.timer_start_events += 1
        events.append('timer.start')
        state.values.update(sessionInfo=deepcopy(received.query['sessionInfo']),
                            currentLoginType='PIN', defaultLoginType='1', isLogin=True)
        events.append('pin_success.login_set')
        return result('success', 'completed')
    if name == 'auth.datetime':
        state.values['currentDateTime'] = received.query.get('currentDateTime')
        events.append('datetime.update')
        return result('success', 'completed')
    if name == 'auth.device-status':
        state.device_status_success(received.query)
        events.extend(('device_status.flags_update', 'favorite.change_context'))
        return result('success', 'completed')
    return result(received.callback, 'presenter_not_replayed')
