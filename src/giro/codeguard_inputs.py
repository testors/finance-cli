"""getNonce's artifact-to-digest arithmetic, separate from environment collection.

No files or private app storage are opened. These explicit bytes must describe
what the original calls actually read. This is not a substitute for resolving
PackageManager/JNI errors or checking whether an installed artifact is current.
"""
from dataclasses import dataclass
import hashlib

from .codeguard_codec import java_utf8, jni_modified_utf8
from .codeguard_rule import AnalysisLimit


@dataclass(frozen=True, repr=False)
class NonceArtifacts:
    codeguard_library: bytes
    image_decoder_library: bytes
    classes_dex: bytes
    manifest_mf: bytes | None
    cert_sf: bytes | None
    signer_certificate_der: bytes


def fallback_nonce_key(challenge):
    """Fallback used only when decoded HASH_KEY is empty."""
    return hashlib.sha256(java_utf8(challenge)).hexdigest().upper().encode('ascii')


def package_digest(package_bytes):
    """Tn02n4sQDWlsjx: sourceDir file SHA256, not classes.dex SHA256.

    Caller supplies bytes actually read from the resolved ApplicationInfo path.
    This arithmetic helper does not stand in for the preceding JNI/process
    checks. Native signed-int file-size overflow remains unmodeled.
    """
    if not isinstance(package_bytes, bytes):
        raise AnalysisLimit('sourceDir file bytes have not been resolved')
    if len(package_bytes) >= 0x80000000:
        raise AnalysisLimit('native signed file-size overflow')
    return hashlib.sha256(package_bytes).digest()


def nonce_artifact_codes(artifacts, challenge, *, is_mix, is_split):
    """Six uppercase hex strings in the native pointer-array order.

    None for manifest/SF means a KNOWN failed fopen, not an unknown file that
    may be silently omitted. In split mode the native branch doesn't read
    these two files. The other four inputs must be supplied explicitly.
    """
    if type(is_mix) is not bool or type(is_split) is not bool:
        raise TypeError('mix/split must be explicit observed booleans')
    suffix = jni_modified_utf8(challenge)
    if is_mix and suffix is None:
        raise AnalysisLimit('native strlen(NULL) on mix challenge')
    if suffix is not None:
        suffix = suffix.split(b'\0', 1)[0]
    sha = lambda data: hashlib.sha256(data).digest()
    hex_bytes = lambda data: data.hex().upper().encode('ascii')
    def require_bytes(data):
        if not isinstance(data, bytes):
            raise AnalysisLimit('required native artifact input has not been resolved')
        return data
    def mix(digest):
        return sha(digest+suffix) if is_mix else digest
    result = [hex_bytes(mix(sha(require_bytes(data)))) for data in (
        artifacts.codeguard_library, artifacts.image_decoder_library, artifacts.classes_dex)]
    for data in (artifacts.manifest_mf, artifacts.cert_sf):
        digest = bytes(32) if is_split or data is None else sha(require_bytes(data))
        result.append(hex_bytes(mix(digest)))
    # Signer differs: PackageManager.signatures[0] -> X.509.getEncoded() ->
    # SHA256 -> uppercase hex BEFORE optional SHA256(hex64 + challenge).
    signer_hex = hex_bytes(sha(require_bytes(artifacts.signer_certificate_der)))
    result.append(hex_bytes(sha(signer_hex+suffix)) if is_mix else signer_hex)
    return tuple(result)
