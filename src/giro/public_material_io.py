"""Explicit, bounded public-certificate IO; never app-private cache or PIN IO.

LDAP endpoints must be explicitly configured before DNS/socket use. Authentication
supplies its public directory endpoint. Cache is an explicitly supplied existing directory.
Policy/budget limits are diagnostics, NOT fabricated SDK IO failures. Acquired
bytes remain untrusted until the mandatory independent validation pipeline.
"""
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import socket
import stat
import secrets

from .android_json import java_integer, NumberSyntaxError
from .codeguard_rule import AnalysisLimit
from .cert_factory import CertificateBackendLimit
from .cert_acquisition import LDAPValues, ObservedReadFailure
from .cert_pipeline import public_store_steps
from .ldap_codec import LdapIOError, LdapReplay, exchange_steps, read_frame


class MaterialAccessLimit(CertificateBackendLimit):
    """CLI access/resource boundary; not an app rejection or cache miss."""


class PublicCache:
    """Single-directory regular-file cache, no path traversal/symlink/hardlink.

    Only public cert/CRL bytes. Writes retain original truncate/write semantics
    AFTER descriptor safety checks. No implicit directory creation/deletion.
    """
    def __init__(self,directory, *, max_bytes):
        if type(max_bytes) is not int or max_bytes<1:
            raise MaterialAccessLimit('explicit positive cache byte budget required')
        path=Path(directory)
        if not path.is_absolute(): raise MaterialAccessLimit('explicit absolute CLI cache directory required')
        try: self._fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        except OSError: raise MaterialAccessLimit('CLI public cache directory unavailable') from None
        self.max_bytes=max_bytes

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd=None

    def __enter__(self): return self
    def __exit__(self,*_): self.close()

    def _open(self,key, *, writing):
        if self._fd is None: raise MaterialAccessLimit('public cache is closed')
        if type(key) is not str or not key or key in ('.','..') or '/' in key or '\x00' in key:
            raise MaterialAccessLimit('cache key requires out-of-scope path interpretation')
        # Refuse special files without waiting on FIFO opens. O_TRUNC is
        # deliberately delayed until AFTER fstat safety/hardlink checks.
        flags=(os.O_WRONLY|os.O_CREAT) if writing else os.O_RDONLY
        try: fd=os.open(key,flags|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self._fd)
        except OSError as error:
            if error.errno==errno.ELOOP:
                raise MaterialAccessLimit('cache symlink refused') from None
            raise
        try: info=os.fstat(fd)
        except OSError:
            os.close(fd)
            raise
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
            os.close(fd)
            raise MaterialAccessLimit('cache file is not an unshared regular file')
        return fd

    def read(self,key):
        try:
            fd=self._open(key,writing=False)
            try:
                data=bytearray()
                while True:
                    chunk=os.read(fd,min(65536,self.max_bytes+1-len(data)))
                    if not chunk: return bytes(data)
                    data.extend(chunk)
                    if len(data)>self.max_bytes:
                        raise MaterialAccessLimit('public cache byte budget reached')
            finally: os.close(fd)
        except OSError:
            return ObservedReadFailure()  # actual read/open failure, not assumed absence

    def write(self,key,data):
        if type(data) is not bytes: raise MaterialAccessLimit('explicit public encoded bytes required')
        if len(data)>self.max_bytes: raise MaterialAccessLimit('public cache write byte budget reached')
        try:
            fd=self._open(key,writing=True)
            try:
                os.ftruncate(fd,0)
                remaining=memoryview(data)
                while remaining:
                    count=os.write(fd,remaining)
                    if count<=0: raise OSError('write returned no bytes')
                    remaining=remaining[count:]
            finally: os.close(fd)
            return 'written'
        except OSError: return 'io_error'  # original ordinary issuer/CRL write is nonfatal


class _BudgetSocketReader:
    def __init__(self,connection,budget):
        self.connection,self.budget,self.used=connection,budget,0

    def read(self,size):
        # Refuse a declared oversized payload BEFORE allocating/receiving it.
        if size>self.budget-self.used:
            raise MaterialAccessLimit('public LDAP receive byte budget reached')
        data=self.connection.recv(size)
        self.used+=len(data)
        return data


@dataclass(frozen=True,repr=False)
class PublicLdapResult:
    replay: LdapReplay
    network_attempted: bool
    # Python DNS/address selection/cleanup differs from unverified Android IO.
    transport_equivalence_verified: bool = False


class PublicLdapClient:
    """Anonymous public LDAP only; endpoint opt-in before any DNS resolution.

    Original is plain TCP even for other URI schemes. This adapter restricts
    use to explicitly permitted ldap endpoints, rather than silently treating
    ldaps as plaintext. No referrals, retries, arbitrary search or credentials.
    """
    def __init__(self, *, allowed_endpoints, timeout_ms, max_bytes, locale_language):
        if type(timeout_ms) is not int or not 0<timeout_ms<=60000:
            raise MaterialAccessLimit('explicit bounded positive LDAP timeout required')
        if type(max_bytes) is not int or max_bytes<1:
            raise MaterialAccessLimit('explicit positive LDAP byte budget required')
        if not isinstance(allowed_endpoints,(tuple,list,set,frozenset)):
            raise MaterialAccessLimit('explicit LDAP endpoint allowlist required')
        endpoints=[]
        for pair in allowed_endpoints:
            if (not isinstance(pair,(tuple,list)) or len(pair)!=2 or type(pair[0]) is not str
                or not pair[0] or type(pair[1]) is not int or not 0<pair[1]<=65535):
                raise MaterialAccessLimit('invalid public LDAP endpoint policy')
            endpoints.append((pair[0].lower(),pair[1]))
        self.allowed=frozenset(endpoints)
        self.timeout_ms,self.max_bytes,self.locale_language=timeout_ms,max_bytes,locale_language
        self.network_attempted=False

    def fetch(self,location):
        self.network_attempted=False
        if location.scheme.lower()!='ldap':
            raise MaterialAccessLimit('only explicitly permitted public ldap scheme is supported')
        try: port=java_integer(location.port,bits=32)
        except (NumberSyntaxError,AnalysisLimit):
            raise MaterialAccessLimit('LDAP endpoint port conversion boundary') from None
        if (location.host.lower(),port) not in self.allowed:
            raise MaterialAccessLimit('public LDAP endpoint has not been enabled')
        # SecureRandom.nextInt(Integer.MAX_VALUE); constructor maps zero to 1.
        # Use a fresh independent CSPRNG draw, not a fixed protocol identifier.
        message_id=secrets.randbelow(2147483647) or 1
        connection=None
        try:
            # Actual TCP implementation; no application/SDK or native library.
            # Multi-address DNS behavior is explicitly NOT called Android-equal.
            self.network_attempted=True
            connection=socket.create_connection((location.host,port),timeout=self.timeout_ms/1000)
            connection.settimeout(self.timeout_ms/1000)
        except OSError:
            if connection is not None:
                try: connection.close()
                except OSError: pass
            return PublicLdapResult(LdapReplay(0,(),(),failure_stage='connect',io_error='connect_io'),True)
        reader=_BudgetSocketReader(connection,self.max_bytes)
        generator=exchange_steps(location,message_id=message_id,locale_language=self.locale_language)
        value,error=None,None
        try:
            while True:
                try: effect=generator.throw(error) if error is not None else generator.send(value)
                except StopIteration as done: return PublicLdapResult(done.value,True)
                error=None
                try:
                    if effect.kind=='read_frame': value=read_frame(reader)
                    elif effect.kind=='write_frame':
                        try: connection.sendall(effect.data)
                        except OSError: raise LdapIOError('frame_write_io') from None
                        value=None
                    else: raise MaterialAccessLimit('unmodeled public LDAP transport effect')
                except LdapIOError as exc: error=exc
        finally:
            # Resource cleanup on backend/policy limits too; never install an
            # anchor or declare an incomplete response successful.
            try: connection.close()
            except OSError: pass


class PublicMaterialExecutor:
    """Connect real cache/LDAP with bounded public store selectors.

    CTL trust mutation/SDK recipient installation are NOT implemented here.
    A missing adapter raises a diagnostic, never empty cache/store success.
    """
    def __init__(self, *, stores, cache=None, ldap=None):
        self.stores,self.cache,self.ldap=tuple(stores),cache,ldap
        self.network_attempted=False
        self.transport_equivalence_verified=False
        self.cache_io_warnings=0

    def _reply(self,effect):
        if effect.kind in ('read_certificate_cache','read_crl_cache'):
            if self.cache is None: raise MaterialAccessLimit('public cache adapter is not configured')
            return self.cache.read(effect.cache_key)
        if effect.kind in ('write_certificate_cache','write_crl_cache'):
            if self.cache is None: raise MaterialAccessLimit('public cache adapter is not configured')
            outcome=self.cache.write(effect.cache_key,effect.data)
            if outcome=='io_error': self.cache_io_warnings+=1
            return outcome
        if effect.kind in ('ldap_certificate','ldap_crl','ldap_ctl'):
            if self.ldap is None: raise MaterialAccessLimit('public LDAP adapter is not configured')
            try: result=self.ldap.fetch(effect.location)
            finally: self.network_attempted |= self.ldap.network_attempted
            return LDAPValues(result.replay.code,result.replay.values)
        raise MaterialAccessLimit('recipient acquisition effect has no configured executor')

    def run(self,generator):
        routed=public_store_steps(generator,self.stores)
        value,error=None,None
        while True:
            try: effect=routed.throw(error) if error is not None else routed.send(value)
            except StopIteration as done:
                if isinstance(done.value,dict):
                    # The pure rule body cannot know its executor used IO.
                    # Never retain its offline=True after a socket attempt.
                    return {**done.value,'offline':not self.network_attempted,
                        'network_attempted':self.network_attempted,
                        'io_observation_scope':'executor_lifetime',
                        'transport_equivalence_verified':self.transport_equivalence_verified,
                        'cache_io_warnings':self.cache_io_warnings}
                return done.value
            error=None
            try: value=self._reply(effect)
            except Exception as exc: error=exc
