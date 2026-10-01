"""Pinned public recipient roots, independent of an installed mobile runtime.

Public directory data cannot choose new trust anchors: exact DER SHA-256 pins
are checked before parsing, use or cache writes. Preparation is explicit and
bounded to two anonymous LDAP exchanges. Loading never accesses the network.
Root acquisition is not recipient validation or successful authentication.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path

from .cert_acquisition import parse_certificate
from .errors import GiroError
from .ldap_codec import parse_uri
from .public_material_io import PublicCache, PublicLdapClient


@dataclass(frozen=True)
class RootSpec:
    name: str
    filename: str
    sha256: str

    @property
    def uri(self):
        return ('ldap://ds.yessign.or.kr:389/cn=' + self.name +
                ',ou=Korea Certification Authority Central,o=KISA,c=KR?cacertificate')


ROOTS = (
    RootSpec('KISA RootCA 1', 'KISARootCA1_4.cer',
             '6fdb3f76c8b801a75338d8a50a7c02879f6198b57e594d318d3832900fedcd79'),
    RootSpec('KISA RootCA 4', 'KISARootCA4_1.cer',
             'a002ff556c601863b08b9aa33a8e6666e97e72bbe552f66eb9f2395c68c7bc98'),
)
PUBLIC_ENDPOINT = ('ds.yessign.or.kr', 389)
MATERIAL_LIMIT = 8 * 1024 * 1024


def _pinned(data, spec):
    return isinstance(data, bytes) and hashlib.sha256(data).hexdigest() == spec.sha256


def load_anchors(cache):
    """Exact configured roots only. Validity is checked when building a path.

    An expired unused root remains part of the configuration; loading it does
    not permit an expired anchor to pass the mandatory recipient path checks.
    """
    anchors = []
    for spec in ROOTS:
        data = cache.read(spec.filename)
        if not _pinned(data, spec):
            raise GiroError('수신자 검증용 공개 루트 자료가 없거나 고정 해시와 다릅니다.')
        anchors.append(parse_certificate(data))
    return tuple(anchors)


def prepare_trust(directory=None, *, send=False):
    """Prepare a caller-owned public cache; no directory creation or retries."""
    report = {'operation': 'public_trust_preparation', 'prepared': False,
              'network_attempted': False, 'ldap_requests': 0, 'maximum_ldap_requests': 2,
              'endpoint': 'ds.yessign.or.kr:389', 'anonymous_bind': True,
              'recipient_validated': False, 'live_login_ready': False,
              'roots': [], 'processing_issues': []}
    if not send:
        return {**report, 'plan_only': True, 'cache_accessed': False}
    report.update(plan_only=False, cache_accessed=False)
    try:
        if directory is None:
            raise GiroError('공개 자료 캐시 경로가 필요합니다.')
        with PublicCache(Path(directory), max_bytes=MATERIAL_LIMIT) as cache:
            report['cache_accessed'] = True
            ldap = PublicLdapClient(allowed_endpoints=(PUBLIC_ENDPOINT,), timeout_ms=10000,
                                   max_bytes=MATERIAL_LIMIT, locale_language='ko')
            for spec in ROOTS:
                row = {'root': spec.name, 'pinned_material_verified': False,
                       'cache_ready': False, 'source': 'cache'}
                report['roots'].append(row)
                data = cache.read(spec.filename)
                if not _pinned(data, spec):
                    row['source'] = 'ldap'
                    report['ldap_requests'] += 1
                    try:
                        result = ldap.fetch(parse_uri(spec.uri))
                    finally:
                        report['network_attempted'] |= ldap.network_attempted
                    if result.replay.code != 1:
                        report['processing_issues'].append('public_root_acquisition_incomplete')
                        break
                    data = next((value for value in result.replay.values or ()
                                 if _pinned(value, spec)), None)
                    if data is None:
                        report['processing_issues'].append('public_root_pin_not_found')
                        break
                parse_certificate(data)
                row['pinned_material_verified'] = True
                if row['source'] == 'ldap':
                    try:
                        row['cache_ready'] = cache.write(spec.filename, data) == 'written'
                    except Exception:
                        row['cache_ready'] = False
                    if not row['cache_ready']:
                        report['processing_issues'].append('public_root_cache_write_failed')
                        break
                else:
                    row['cache_ready'] = True
            report['prepared'] = len(report['roots']) == len(ROOTS) and all(
                row['cache_ready'] for row in report['roots'])
    except Exception:
        report['processing_issues'].append('public_trust_preparation_incomplete')
    return report
