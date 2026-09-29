"""Bounded Android X500Principal/selector adapters for explicit public stores.

Not SDKName.equals: RDN order, string tag and keyword rules differ. Unknown
Unicode/multi-AVA/provider cases are analysis limits, not nonmatches. Several
distinct selected values require real HashSet order; never pick input[0].
"""
from dataclasses import dataclass

from .cert_factory import _node, SET, OID, CertificateBackendLimit
from .cert_material import _members, _kind, _integer, CertificateMaterial, CRLMaterial
from .cert_signatures import _require_stable_der
from .cert_acquisition import ObservedStoreFailure

_KEYWORDS = {'2.5.4.3':'cn','2.5.4.6':'c','2.5.4.7':'l','2.5.4.8':'st',
             '2.5.4.10':'o','2.5.4.11':'ou','2.5.4.9':'street',
             '0.9.2342.19200300.100.1.25':'dc','0.9.2342.19200300.100.1.1':'uid'}
_PRINTABLE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")
_ESCAPE = frozenset(',+<>;"\\')


def _rdns(data):
    from asn1crypto.core import ObjectIdentifier
    node = _node(data)
    _require_stable_der(node)
    result=[]
    for rdn in _members(node):
        values=[]
        for ava in _kind(rdn,SET).children():
            parts = _members(ava,2)
            if len(parts)!=2: raise CertificateBackendLimit('Android AVA trailing fields boundary')
            oid = ObjectIdentifier.load(_kind(parts[0],OID).encoded).dotted
            values.append((oid,parts[1]))
        result.append(values)
    return result


def principal_canonical(data):
    result=[]
    for values in reversed(_rdns(data)):
        if len(values)!=1:
            raise CertificateBackendLimit('Android multi-AVA canonical ordering boundary')
        oid,value = values[0]
        key = _KEYWORDS.get(oid)
        if key is None or value.kind not in ((0,0,12),(0,0,19),(0,0,20)):
            result.append((key or oid)+'=#'+value.encoded.hex())
            continue
        if not value.contents.isascii():
            raise CertificateBackendLimit('Android principal Unicode UTF8/case/NFKD boundary')
        text=value.contents.decode('ascii')
        escaped=[]
        previous_space=False
        for index,char in enumerate(text):
            special = char in _ESCAPE or (index==0 and char=='#')
            if char not in _PRINTABLE and not special:
                raise CertificateBackendLimit('Android principal debug/nonprintable canonical boundary')
            if special: escaped.append('\\')
            if char==' ':
                if not previous_space: escaped.append(char)
                previous_space=True
            else:
                previous_space=False
                escaped.append(char)
        result.append(key+'='+''.join(escaped).strip(' ').lower())
    return ','.join(result)


def principal_equal(left,right):
    if left==right:
        _rdns(left)  # canonical DER/AVA shape, no guessed Unicode normalization
        return True
    return principal_canonical(left)==principal_canonical(right)


def unique_selection(values):
    by_encoding={}
    for value in values: by_encoding.setdefault(value.data,value)
    if len(by_encoding)>1:
        raise CertificateBackendLimit('multiple selected materials require Android HashSet iteration order')
    return tuple(by_encoding.values())


@dataclass(frozen=True,repr=False)
class MaterialStore:
    certificates: tuple = ()
    crls: tuple = ()

    def certificates_for_subject(self,subject):
        return unique_selection(c for c in self.certificates
            if isinstance(c,CertificateMaterial) and principal_equal(subject,c.subject_der))

    def crls_for_issuer(self,issuer, *, bounds=None):
        selected=[]
        for crl in self.crls:
            if not isinstance(crl,CRLMaterial) or not principal_equal(issuer,crl.issuer_der): continue
            if bounds is not None:
                number = crl.extensions.get('2.5.29.20')
                if number is None:
                    # Runtime selector constructs DerInputStream(null), not an
                    # automatic false. Exact platform exception adapter pending.
                    raise CertificateBackendLimit('Android CRL-number selector null extension boundary')
                value=_integer(number)
                if value<0: raise CertificateBackendLimit('Android negative CRL-number selector boundary')
                if not bounds[0]<=value<=bounds[1]: continue
            selected.append(crl)
        return unique_selection(selected)


def select_material_effect(effect, stores):
    if effect.kind=='anchor_match':
        return principal_equal(effect.target.issuer_der,effect.candidate.subject_der)
    store=stores[effect.index]
    if isinstance(store,ObservedStoreFailure): return store
    if not isinstance(store,MaterialStore):
        raise CertificateBackendLimit('explicit public material store required')
    if effect.kind=='issuer_store': return store.certificates_for_subject(effect.target.issuer_der)
    if effect.kind=='crl_store': return store.crls_for_issuer(effect.candidate.subject_der)
    if effect.kind=='delta_crl_store':
        chosen,bounds=effect.candidate
        return store.crls_for_issuer(chosen.issuer_der,bounds=bounds)
    raise CertificateBackendLimit('unmodeled public material selection effect')
