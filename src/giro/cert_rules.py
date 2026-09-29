"""Offline yessign-compatible PKIX rules.

These functions assume already decoded fields and the caller's preceding
checks. Passing them is NOT certificate/path/CRL validation or permission to
install a recipient. No trust, signature, LDAP, CTL, name-constraint, IDP or
delta-CRL processing is skipped by a live client: no live client uses this yet.
"""
from dataclasses import dataclass, replace
from datetime import datetime

ANY_POLICY = '2.5.29.32.0'
DEFAULT_POLICIES = frozenset(('1.2.410.200004.2.1',) +
                             tuple(f'1.2.410.200005.1.1.{i}' for i in range(1, 6)))
EKU_MASKS = {
    '1.3.6.1.5.5.7.3.1': 168,  # serverAuth: digitalSignature | keyEncipherment | keyAgreement
    '1.3.6.1.5.5.7.3.2': 136,
    '1.3.6.1.5.5.7.3.3': 128,
    '1.3.6.1.5.5.7.3.4': 232,
    '1.3.6.1.5.5.7.3.8': 192,
    '1.3.6.1.5.5.7.3.9': 192,
}
HANDLED_CRITICAL = frozenset('2.5.29.' + suffix for suffix in
                            ('15', '32', '33', '54', '28', '27', '36', '19', '17', '30', '37'))


class CertificateRuleError(ValueError):
    """An observed SDK sub-rule failed, NOT a Giro response/callback code."""
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def java_int(value):
    return (value + 2**31) % 2**32 - 2**31


@dataclass(frozen=True)
class PolicyState:
    allowed: frozenset[str]
    explicit: int
    inhibit_any: int
    licensed_ca: bool

    @classmethod
    def initial(cls, count, *, initial_policies=DEFAULT_POLICIES, licensed_ca,
                explicit_required=True, any_inhibited=False):
        # count excludes the trust anchor. licensed_ca is derived by the caller
        # from the SDK-rendered highest path certificate subject, NOT the leaf.
        return cls(frozenset(initial_policies), 0 if explicit_required else count+1,
                   0 if any_inhibited else count+1, licensed_ca)

    def step(self, policies, *, target=False, self_issued=False,
             require_explicit=None, inhibit_any=None):
        return self.select(policies).advance(target=target,self_issued=self_issued,
                     require_explicit=require_explicit,inhibit_any=inhibit_any)

    def select(self, policies):
        """Process root-nearest -> leaf, preserving list length and duplicates.

        SDK's LicensedCA branch retains the incoming allow-set and compares
        intersection *set size* with policy *sequence size*. Other paths carry
        the intersection forward. Allowed anyPolicy breaks iteration early.
        PolicyMappings are not applied by this bytecode.
        """
        selected = set()
        if policies is not None:
            for oid in policies:
                if oid == ANY_POLICY and self.inhibit_any != 0:
                    selected = set(self.allowed)
                    break
                if oid in self.allowed:
                    selected.add(oid)
        if self.explicit == 0 and not selected:
            raise CertificateRuleError('certificate_policy_empty_or_unaccepted')
        if self.licensed_ca:
            if policies is None:
                # explicit=false can reach the original's sequence.size NPE.
                raise CertificateRuleError('licensed_policy_null_sequence')
            if len(selected) != len(policies):
                raise CertificateRuleError('licensed_policy_count_mismatch')
            allowed = self.allowed
        else:
            allowed = frozenset(selected)
        return replace(self,allowed=allowed)

    def advance(self, *, target=False, self_issued=False,
                require_explicit=None, inhibit_any=None):
        """Counter stage, separate to preserve interleaved NameConstraints checks."""
        explicit, any_counter = self.explicit, self.inhibit_any
        if not self_issued:
            if explicit != 0:
                explicit -= 1
            if not target and any_counter != 0:
                any_counter -= 1
        # CA constraints are handled only in its non-self-issued branch;
        # the leaf's requireExplicitPolicy is handled even if self-issued.
        if target or not self_issued:
            if require_explicit is not None:
                value = java_int(require_explicit)
                if value != -1 and value < explicit:
                    explicit = value
            if not target and inhibit_any is not None:
                value = java_int(inhibit_any)
                if value < any_counter:
                    any_counter = value
        if target and explicit == 0 and not self.allowed:
            raise CertificateRuleError('final_policy_set_empty')
        return replace(self, explicit=explicit, inhibit_any=any_counter)


def check_extended_key_usage(key_usage_mask, eku_oids):
    """All EKUs must match one of six OIDs and its KU mask, if BOTH exist.

    KU uses DERBitString/KeyUsage's low-byte representation (bit 0 = 128).
    Missing KU/EKU returns here; recipient/CA KU checks are separate gates.
    No hostname/serverAuth requirement is invented for the CMS recipient.
    """
    if key_usage_mask is None or eku_oids is None:
        return
    for oid in eku_oids:
        if not (key_usage_mask & EKU_MASKS.get(oid, 0)):
            raise CertificateRuleError('extended_key_usage_mismatch')


def check_recipient_key_usage(key_usage_mask):
    # CertVerifier.a performs this AFTER buildAndValidate, not before it.
    if key_usage_mask is None or not key_usage_mask & 32:
        raise CertificateRuleError('recipient_key_encipherment_required')


def check_ca_constraints(*, version, is_ca, path_length, self_issued,
                         remaining_path, key_usage_mask):
    """Non-target certificates only; target CA/basicConstraints not added."""
    remaining_path = check_ca_structure(version=version,is_ca=is_ca,path_length=path_length,
                       self_issued=self_issued,remaining_path=remaining_path)
    if key_usage_mask is None or not key_usage_mask & 4:
        raise CertificateRuleError('ca_key_cert_sign_required')
    return remaining_path


def check_ca_structure(*, version, is_ca, path_length, self_issued, remaining_path):
    """Stage before getKeyUsage() decoding in the path loop."""
    if version == 1:
        raise CertificateRuleError('v1_cannot_be_ca')
    if is_ca is None:
        raise CertificateRuleError('ca_basic_constraints_missing')
    if not is_ca:
        raise CertificateRuleError('basic_constraints_not_ca')
    if not self_issued:
        if remaining_path <= 0:
            raise CertificateRuleError('maximum_path_length_exhausted')
        remaining_path -= 1
    if path_length is not None:
        remaining_path = min(remaining_path, java_int(path_length))
    return remaining_path


def unhandled_critical(critical_oids, *, version=3):
    # No custom PKIXCertPathCheckers are installed in the observed wrapper.
    return frozenset() if version != 3 else frozenset(critical_oids) - HANDLED_CRITICAL


def check_crl_window(this_update, next_update, at):
    if this_update is None or next_update is None:
        raise CertificateRuleError('crl_update_time_missing')
    if at < this_update:
        raise CertificateRuleError('crl_not_yet_valid')
    if at > next_update:
        raise CertificateRuleError('crl_expired')


def check_crl_signer_usage(key_usage_mask, *, is_trust_anchor):
    if not is_trust_anchor and (key_usage_mask is None or not key_usage_mask & 2):
        raise CertificateRuleError('issuer_crl_sign_required')


def check_revocation_entry(revocation_date: datetime | None, at: datetime):
    if revocation_date is not None:
        raise CertificateRuleError('revocation_date_in_future' if at < revocation_date
                                   else 'certificate_revoked')


def crl_attribute(*, target, issuer_name_equals_root_name):
    # Exact rendered String.equals in engineValidate, NOT a general DN compare.
    return ('certificaterevocationlist' if target and not issuer_name_equals_root_name
            else 'authorityrevocationlist')


def crl_source_action(*, store_had_candidates, valid_store_candidate):
    if store_had_candidates:
        if not valid_store_candidate:
            raise CertificateRuleError('stored_crls_present_but_invalid')
        return 'use_store'
    return 'find_crl'  # cache/LDAP stage needed; NEVER executed here


def check_missing_idp(*, licensed_ca, issuer_name_lower):
    # The caller must supply Android/SDK-rendered, locale-lowercased DN.
    if not licensed_ca and 'o=kisa' not in issuer_name_lower:
        raise CertificateRuleError('rfc3280_crl_idp_missing')
