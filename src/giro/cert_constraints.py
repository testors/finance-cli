"""Offline transcription of yessign PKIXNameConstraints, not generic RFC PKIX.

Preserves sequential subtree intersections, SDK split/URI parsing, mailbox
index quirks and signed-byte IP comparisons. No network or trust installation.
DER inputs must be at the observed constructor boundary; unknown encodings or
Android Unicode case behavior are analysis limits, not certificate rejection.
"""
from dataclasses import dataclass, field

from .cert_factory import _node, CertificateBackendLimit
from .cert_material import _members, _explicit, _kind
from .cert_rules import CertificateRuleError
from .cert_signatures import _require_stable_der

TAGS = (1,2,4,6,7)


def ignore_case(a, b):
    if a == b:
        return True
    if not a.isascii() or not b.isascii():
        raise CertificateBackendLimit('Android equalsIgnoreCase Unicode boundary')
    return a.lower() == b.lower()


def sdk_split(text):
    # com.yessign.util.Strings.split, NOT String.split or Python split.
    parts = []
    while (position := text.find('.')) > 0:
        parts.append(text[:position])
        text = text[position+1:]
    return parts+[text]


def within_domain(name, constraint):
    base = sdk_split(constraint[1:] if constraint.startswith('.') else constraint)
    parts = sdk_split(name)
    if len(parts) <= len(base):
        return False
    start = len(parts)-len(base)
    return bool(parts[start-1]) and all(ignore_case(a,b) for a,b in zip(base,parts[start:]))


def uri_host(text):
    # Original substring sequence, including colon handling BEFORE userinfo.
    text = text[text.find(':')+1:]
    if '//' in text:
        text = text[text.find('//')+2:]
    if ':' in text:
        text = text[:text.rfind(':')]
    text = text[text.find(':')+1:]
    text = text[text.find('@')+1:]
    return text[:text.find('/')] if '/' in text else text


def email_matches(name, base):
    if '@' in base:
        return ignore_case(name,base)
    if not base:
        raise CertificateRuleError('name_constraint_empty_email_base')  # charAt(0)
    domain = name[name.find('@')+1:]
    return within_domain(domain,base) if base[0] == '.' else ignore_case(domain,base)


def dn_within(name, base):
    # ASN1Sequence of RDN SETs, exact type/value/order comparison; no X509Name.
    return bool(base) and len(base) <= len(name) and name[:len(base)] == base


def ip_matches(name, base):
    length = len(name)
    if length != len(base)//2:
        return False
    return all((a & mask) == (b & mask) for a,b,mask in
               zip(name,base[:length],base[length:length*2]))


def _ip_pick(a, b, *, maximum):
    # NOT lexical order: don't stop on the opposite comparison. Also the
    # second operand is (signed byte & 65535), unlike the first's &255.
    for left,right in zip(a,b):
        right = (right if right < 128 else right-256) & 65535
        if (left > right) if maximum else (left < right):
            return a
    return b


def _ip_intersection(a, b):
    if len(a) != len(b):
        return set()
    size = len(a)//2  # original discards odd trailing byte in each range
    a_addr,a_mask,b_addr,b_mask = a[:size],a[size:2*size],b[:size],b[size:2*size]
    low_a = bytes(v&m for v,m in zip(a_addr,a_mask))
    low_b = bytes(v&m for v,m in zip(b_addr,b_mask))
    high_a = bytes((v|(~m))&255 for v,m in zip(low_a,a_mask))
    high_b = bytes((v|(~m))&255 for v,m in zip(low_b,b_mask))
    low = _ip_pick(low_a,low_b,maximum=True)
    high = _ip_pick(high_a,high_b,maximum=False)
    if low != high and _ip_pick(low,high,maximum=True) == low:
        return set()
    return {bytes(x|y for x,y in zip(low_a,low_b))+bytes(x|y for x,y in zip(a_mask,b_mask))}


def _mail_intersection(left, right):
    """Pair used by both email and URI, with different caller orientation."""
    if '@' in left:
        domain = left[left.find('@')+1:]
        if '@' in right:
            return {left} if ignore_case(left,right) else set()
        if right.startswith('.'):
            return {left} if within_domain(domain,right) else set()
        return {left} if ignore_case(domain,right) else set()
    if left.startswith('.'):
        if '@' in right:
            # Original uses LEFT.indexOf('@') (-1), thus passes entire mailbox.
            return {right} if within_domain(right[left.find('@')+1:],left) else set()
        if right.startswith('.'):
            if within_domain(left,right) or ignore_case(left,right):
                return {left}
            return {right} if within_domain(right,left) else set()
        return {right} if within_domain(right,left) else set()
    if '@' in right:
        return {right} if ignore_case(right[right.find('@')+1:],left) else set()
    if right.startswith('.'):
        return {left} if within_domain(left,right) else set()
    return {left} if ignore_case(left,right) else set()


def _mail_union(left, right):
    if '@' in left:
        domain = left[left.find('@')+1:]
        if '@' in right:
            return {left} if ignore_case(left,right) else {left,right}
        if right.startswith('.'):
            return {right} if within_domain(domain,right) else {left,right}
        return {right} if ignore_case(domain,right) else {left,right}
    if left.startswith('.'):
        if '@' in right:
            return {left} if within_domain(right[left.find('@')+1:],left) else {left,right}
        if right.startswith('.'):
            if within_domain(left,right) or ignore_case(left,right):
                return {right}
            return {left} if within_domain(right,left) else {left,right}
        return {left} if within_domain(right,left) else {left,right}
    if '@' in right:
        # Same outer-index bug in both exclusion helpers.
        return {left} if ignore_case(right[left.find('@')+1:],left) else {left,right}
    if right.startswith('.'):
        return {right} if within_domain(left,right) else {left,right}
    return {left} if ignore_case(left,right) else {left,right}


def general_name(node):
    _require_stable_der(node)
    if node.kind[0] != 2 or node.kind[2] not in (0,1,2,4,5,6,7,8):
        raise CertificateRuleError('general_name_unknown_tag')
    tag = node.kind[2]
    if tag in (1,2,6,7,8) and node.kind[1]:
        raise CertificateBackendLimit('GeneralName implicit/explicit boundary')
    if tag in (1,2,6):
        return tag,node.contents.decode('latin1')  # DERIA5String byte&255
    if tag == 4:
        return tag,dn_value(_explicit(node).encoded)
    if tag == 7:
        return tag,node.contents
    if tag == 8:
        from .cms import _tlv
        _require_stable_der(_node(_tlv(6,node.contents)))
    return tag,None  # Other legal name tags are not constrained by this class.


def dn_value(data):
    node = _node(data)
    _require_stable_der(node)
    return tuple(_kind(rdn,(0,1,17)).encoded for rdn in _members(node))


def _subtree(node):
    parts = _members(node,1)
    name = general_name(parts[0])
    if len(parts) not in (1,2,3):
        raise CertificateRuleError('general_subtree_sequence_size')
    for index, part in enumerate(parts[1:],1):
        if part.kind[:2] != (2,0) or not part.contents:
            raise CertificateBackendLimit('GeneralSubtree integer tagging boundary')
        if len(parts) == 2 and part.kind[2] not in (0,1):
            raise CertificateRuleError('general_subtree_tag')
        # When size==3, original doesn't inspect the tag numbers. Values are
        # decoded signed integers, but min/max are NOT used by the validator.
        int.from_bytes(part.contents,'big',signed=True)
    return name


@dataclass(repr=False)
class NameConstraints:
    permitted: dict = field(default_factory=lambda: {tag:None for tag in TAGS})
    excluded: dict = field(default_factory=lambda: {tag:set() for tag in TAGS})

    def intersect(self, tag, value):
        if tag not in TAGS:
            return
        old = self.permitted[tag]
        result = set()
        if old is None:
            result = {value}
        else:
            for prior in old:
                if tag == 4:
                    if dn_within(value,prior): result.add(value)
                    elif dn_within(prior,value): result.add(prior)
                elif tag == 2:
                    # There is deliberately NO equality clause in c(Set,String).
                    if within_domain(prior,value): result.add(prior)
                    elif within_domain(value,prior): result.add(value)
                elif tag == 7:
                    result.update(_ip_intersection(prior,value))
                else:
                    result.update(_mail_intersection(value,prior) if tag == 1
                                  else _mail_intersection(prior,value))
        self.permitted[tag] = result

    def exclude(self, tag, value):
        if tag not in TAGS:
            return
        old = self.excluded[tag]
        result = {value} if not old else set()
        for prior in old:
            if tag == 4:
                if dn_within(value,prior): result.add(prior)
                elif dn_within(prior,value): result.add(value)
                else: result.update((prior,value))
            elif tag == 2:
                if within_domain(prior,value): result.add(value)
                elif within_domain(value,prior): result.add(prior)
                else: result.update((prior,value))
            elif tag == 7:
                result.update((prior,value))
            else:
                result.update(_mail_union(prior,value))
        self.excluded[tag] = result

    def check(self, tag, value):
        if tag not in TAGS:
            return
        def matches(base):
            if tag == 4: return dn_within(value,base)
            if tag == 7: return ip_matches(value,base)
            if tag == 1: return email_matches(value,base)
            if tag == 2: return within_domain(value,base) or ignore_case(value,base)
            host = uri_host(value)
            return within_domain(host,base) if base.startswith('.') else ignore_case(host,base)
        permitted = self.permitted[tag]
        if permitted is not None and not any(matches(base) for base in permitted):
            # Empty names with empty permitted sets pass EXCEPT directoryName.
            if tag == 4 or value or permitted:
                raise CertificateRuleError('name_not_permitted_'+str(tag))
        if any(matches(base) for base in self.excluded[tag]):
            raise CertificateRuleError('name_excluded_'+str(tag))

    def check_der_name(self, data):
        self.check(*general_name(_node(data)))

    def add_extension(self, node):
        if node is None:
            return
        _require_stable_der(node)
        groups = {}
        for part in _members(node):
            if part.kind[0] != 2:
                raise CertificateBackendLimit('NameConstraints tagged group boundary')
            if part.kind[2] in (0,1):
                if not part.kind[1]:
                    raise CertificateBackendLimit('NameConstraints constructed group boundary')
                groups[part.kind[2]] = part.children()  # last duplicate group wins
        # Original visits all permitted first, then excluded, regardless of
        # their encoded order. An empty [0] does not create an empty allow-set.
        for group, method in ((0,self.intersect),(1,self.exclude)):
            for subtree in groups.get(group,()):
                method(*_subtree(subtree))
