"""Synthetic XML, no application/library execution and no network requests."""
import base64
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path
import subprocess
import unittest
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from hometax_cli.invoice_certificate import xml_sign, certificate_selection
from test_certificate import synthetic_material

DS="http://www.w3.org/2000/09/xmldsig#"
XML=b'''<TaxInvoice xmlns="urn:test" xmlns:x="urn:extension"><ExchangedDocument><ID>EXCLUDED</ID></ExchangedDocument><TaxInvoiceDocument><ID>ORIGINAL</ID><x:Value a="1">100 &amp; 200</x:Value></TaxInvoiceDocument></TaxInvoice>'''

class InvoiceSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert,cls.key,_=synthetic_material()
        cls.signed=xml_sign(cls.cert,cls.key,XML)

    def verify(self,xml):
        p=subprocess.run(['java',str(Path(__file__).parents[2]/'src/hometax_cli/InvoiceSigner.java')],
            input=b'\n'.join(base64.b64encode(x) for x in (self.cert,b'',xml))+b'\n',
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        self.assertEqual(p.returncode,0)
        return p.stdout.strip()==b'VALID'

    def test_transform_and_independent_signature_verification(self):
        root=etree.fromstring(self.signed)
        self.assertEqual(etree.QName(root[1]).localname,'Signature')
        info=root.find('.//{'+DS+'}SignedInfo')
        # Independently verify the RSA signature using libxml2 C14N and OpenSSL.
        value=base64.b64decode(root.findtext('.//{'+DS+'}SignatureValue'))
        x509.load_der_x509_certificate(self.cert).public_key().verify(value,
            etree.tostring(info,method='c14n',with_comments=False),padding.PKCS1v15(),hashes.SHA256())
        transforms=root.findall('.//{'+DS+'}Transform')
        self.assertEqual([x.get('Algorithm') for x in transforms],[
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315','http://www.w3.org/TR/1999/REC-xpath-19991116'])
        self.assertTrue(self.verify(self.signed))

    def test_tampered_transaction_is_rejected(self):
        self.assertFalse(self.verify(self.signed.replace(b'ORIGINAL',b'CHANGED')))

    def test_exchanged_document_is_excluded_by_original_xpath(self):
        self.assertTrue(self.verify(self.signed.replace(b'EXCLUDED',b'CHANGED')))

    def test_no_external_entities(self):
        from hometax_cli.certificate import CertificateError
        with self.assertRaises(CertificateError):
            xml_sign(self.cert,self.key,b'<!DOCTYPE TaxInvoice [<!ENTITY x SYSTEM "file:///nonexistent">]><TaxInvoice><TaxInvoiceDocument>&x;</TaxInvoiceDocument></TaxInvoice>')

    def test_worker_signs_two_documents_and_preserves_native_partial_callback(self):
        # Actual worker/PFX/JDK boundary with synthetic credentials only.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(__file__).parent
            subprocess.run(['python',str(root/'make_wire_material.py'),directory],check=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**os.environ,'PYTHONPATH':str(root)})
            data={'pfx':str(Path(directory)/'certificate.pfx'),
                  'password':base64.b64encode(b'OFFLINE FIXTURE PASSWORD').decode(),
                  'xml':XML.decode(),'xml2':XML.decode().replace('ORIGINAL','REPLACEMENT')}
            def worker():
                process=subprocess.run(['python','-m','hometax_cli.invoice_certificate'],
                    input=json.dumps(data),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
                return json.loads(process.stdout)
            result=worker()
            first=base64.b64decode(result['callback']['xmlSigniture'])
            second=base64.b64decode(result['callback']['xmlSigniture2'])
            self.assertIn(b'ORIGINAL',first)
            self.assertIn(b'REPLACEMENT',second)
            self.assertIn(b'<ds:Signature',first)
            self.assertIn(b'<ds:Signature',second)
            data['xml2']='<INVALID'
            result=worker()
            self.assertIn('xmlSigniture',result['callback'])
            self.assertNotIn('xmlSigniture2',result['callback'])
            self.assertEqual(len(result['warnings']),1)
            data['xml']='<INVALID'
            result=worker()
            self.assertEqual(result['callback'],'')
            self.assertEqual(len(result['warnings']),2)

    def test_native_policy_list_matches_whole_attribute(self):
        oid='1.2.410.200004.5.2.1.1'
        cert,_,_=synthetic_material(policies=[oid])
        allowed=oid.replace('.', ' ')+';'
        self.assertTrue(certificate_selection(cert,allowed)['selectable'])
        self.assertFalse(certificate_selection(self.cert,allowed)['selectable'])
        multiple,_,_=synthetic_material(policies=[oid,'1.2.3'])
        self.assertFalse(certificate_selection(multiple,allowed)['selectable'])
        self.assertTrue(certificate_selection(multiple,allowed[:-1]+', 1 2 3;')['selectable'])

    def test_native_expiry_uses_local_calendar_date(self):
        expiry=x509.load_der_x509_certificate(self.cert).not_valid_after_utc.astimezone().date()
        self.assertTrue(certificate_selection(self.cert,'',expiry)['selectable'])
        self.assertFalse(certificate_selection(self.cert,'',expiry+timedelta(days=1))['selectable'])

if __name__=='__main__':unittest.main()
