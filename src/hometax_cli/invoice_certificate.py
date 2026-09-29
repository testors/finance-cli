"""Independent XML signature boundary; credentials travel through pipes only."""
import base64
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys
from cryptography import x509

from .certificate import CertificateError, SignedCertificate, sign_empty, vid_random
from .pfx import read_pfx, select_signing_pair
from finance_cli.core.native import java_executable


def certificate_selection(certificate, oid, today=None):
    """Native g.a: date-only expiry and exact CERT_GetAttribute(14) match."""
    cert = x509.load_der_x509_certificate(certificate)
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
        # DSTK_CERT_GetCertPolicy_PolicyID: space-separated arcs, comma-space
        # between policies. It compares the entire string, not any-policy.
        attribute = ", ".join(p.policy_identifier.dotted_string.replace(".", " ") for p in policies)
    except x509.ExtensionNotFound:
        attribute = ""
    allowed = oid.split(";") if oid else []
    while allowed and allowed[-1] == "":
        allowed.pop()  # Java String.split discards trailing empty entries.
    expired = (today or datetime.now().astimezone().date()) > cert.not_valid_after_utc.astimezone().date()
    matches = not oid or attribute in allowed
    return {"selectable": not expired and matches, "policy_matches": matches,
            "expired_in_original_list": expired, "policy_attribute": attribute,
            "not_after": cert.not_valid_after_utc.isoformat()}


def xml_sign(certificate, private, xml):
    process = subprocess.run([java_executable(), str(Path(__file__).with_name("InvoiceSigner.java"))],
        input=b"\n".join(base64.b64encode(value) for value in (certificate, private, xml)) + b"\n",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
    if process.returncode:
        raise CertificateError("XML 서명을 완료하지 못했습니다. 서비스 발급 결과와는 별개입니다.")
    return base64.b64decode(process.stdout.strip(), validate=True)


def main():
    # The caller supplies the password through stdin, never an argv option.
    data = json.load(sys.stdin)
    if data.get('credential'):
        from finance_cli.credentials.registry import Registry
        certificate, private, warnings = Registry().material(data['credential'], base64.b64decode(data['password']))
    else:
        pairs, warnings = read_pfx(Path(data["pfx"]).read_bytes(), base64.b64decode(data["password"]))
        certificate, private = select_signing_pair(pairs, data.get("pfx_index"))
    selection = certificate_selection(certificate, data.get("oid"))
    if not selection["selectable"]:
        print(json.dumps({"selection": selection, "warnings": warnings}))
        return
    result = SignedCertificate(sign_empty(certificate, private), vid_random(private), warnings).callback()["payload"]
    # XMLSIGNITURE uses vidRandom; login's otherwise identical callback uses randomEnc.
    result["vidRandom"] = result.pop("randomEnc")
    # Preflight is entirely local and checks Java/XML signing before any C02.
    documents = [data.get("xml",
        '<TaxInvoice><TaxInvoiceDocument><ID>LOCAL PREFLIGHT</ID></TaxInvoiceDocument></TaxInvoice>')]
    if "xml2" in data:
        documents.append(data["xml2"])
    signatures = []
    for document in documents:
        try:
            signatures.append(xml_sign(certificate, private, document.encode("utf-8")))
        except CertificateError:
            if "xml" not in data:
                raise  # local preflight must finish before any request
            # Native g.e skips a document whose XML signature fails. The page
            # then applies its own single/dual signature presence condition.
            warnings.append("XML 문서 서명을 완료하지 못했습니다. 서비스 콜백의 판정을 따릅니다.")
    result.update(certResult="SUCC")
    for index, signature in enumerate(signatures):
        result["xmlSigniture" + ("2" if index else "")] = base64.b64encode(signature).decode("ascii")
    # stdout is a private parent-process pipe, not the command's public output.
    print(json.dumps({"callback":(result if signatures else "") if "xml" in data else None,
                      "selection":selection,"warnings":warnings}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("XML 인증서 처리 오류 (" + type(error).__name__ + ")", file=sys.stderr)
        sys.exit(2)
