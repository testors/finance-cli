"""Synthetic encrypted exchanges for every bill service; no institution traffic."""
from http.cookiejar import CookieJar
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from giro.bill_catalog import BILL_TYPES, INPUTS, OWN_TYPES, REGION_TYPES, SIMPLE_TYPES
from giro.bills import normalize_pages, due_bills
from giro.client import AuthenticatedClient, AuthenticatedSession, WireResponse
from giro.crypto import decrypt_text
from giro.errors import GiroError
from giro.protocol import ENDPOINTS
from giro.query_flow import collect_bills, collect_detail, collect_summary, list_bills
from giro.__main__ import parser, run

KEY = bytes(range(16))


class Queries(unittest.TestCase):
    def setUp(self):
        self.session = AuthenticatedSession('SYNTHETIC-DEVICE', KEY, CookieJar(), 'SYNTHETIC/1', 'PIN', {'hasUIDInfoYn': 'Y'})
        self.client = AuthenticatedClient(self.session)
        self.calls = []
        self.responses = {}
        self.enterContext(patch('giro.client._post', side_effect=self.exchange))

    def exchange(self, path, body, headers):
        fields = parse_qs(decrypt_text(parse_qs(body.decode())['encryptedData'][0], KEY), keep_blank_values=True)
        self.calls.append((path, fields))
        reply = self.responses[path]
        if callable(reply): reply = reply(fields)
        return WireResponse(200, [], json.dumps(reply).encode())

    def reply(self, name, value):
        self.responses[ENDPOINTS[name].path] = value

    def prepare(self, kind):
        row = dict(elecNo='SYNTHETIC-BILL', giroNo='SYNTHETIC-GIRO', sortCode='SYNTHETIC-SORT',
            key='SYNTHETIC-KEY', customerNo='SYNTHETIC-CUSTOMER', companyName='합성기관', taxName='합성요금',
            payMny='2000', napbuMny='2000', payLimitDate='20261031', pay1date='20261031')
        page = dict(responseCode='000', paymentList=[row],
                    pageNaviMap=dict(currentPage='1', totalPage='1', totalCount='1'))
        self.reply(kind+'.list', page)
        self.reply(kind+'.detail', dict(responseCode='000', paymentData=row))
        if kind in REGION_TYPES:
            self.reply(kind+'.provinces', dict(responseCode='000', provinceList=[dict(areaCode='01', areaName='합성시')]))
            self.reply(kind+'.districts', dict(responseCode='000', districtList=[dict(sortCode='01', giroNo='1234567', sigunguName='합성구')]))
        if kind == 'giro': self.reply('giro.lookup', dict(responseCode='000', giroNo='1234567', searchPayYn='Y'))
        return {key: '1234567890' for key in INPUTS[kind]}

    def test_every_type_list_detail_wire_and_private_events(self):
        for kind in BILL_TYPES:
            with self.subTest(kind=kind):
                self.calls.clear()
                result = collect_bills(self.client, kind, search=self.prepare(kind))
                self.assertTrue(result['app_success'], result)
                self.assertTrue(result['complete'], result)
                self.assertEqual(result['bills'][0]['amount'], 2000)
                fields = self.calls[-1][1]
                if kind in OWN_TYPES: self.assertEqual(fields['useUIDInfoYn'], ['Y'])
                else: self.assertNotIn('useUIDInfoYn', fields)
                if kind in SIMPLE_TYPES: self.assertNotIn('page', fields)
                if kind == 'nontax':
                    self.assertTrue(all(c[1].get('tongYn') == ['Y'] for c in self.calls))
                if kind == 'giro':
                    self.assertNotIn('pageSize', fields)
                    self.assertIsNone(result['bills'][0]['due_date'], 'pay1date is not a due date')
                details = collect_detail(self.client, kind, result['bills'][0]['identifiers'])
                self.assertTrue(details['app_success'], details)
                if kind in REGION_TYPES or kind == 'water':
                    self.assertNotIn('giroNo', self.calls[-1][1])
                    self.assertNotIn('sortCode', self.calls[-1][1])
                if kind == 'nontax': self.assertEqual(self.calls[-1][1]['tongYn'], ['Y'])
                if kind in ('social', 'annuity'):
                    self.assertEqual(self.calls[-1][1]['customerNo'], ['SYNTHETIC-CUSTOMER'])
                if kind in ('kepco', 'ktcomm', 'tv', 'giro'):
                    self.assertEqual(self.calls[-1][1]['key'], ['SYNTHETIC-KEY'])
                self.assertNotIn('SYNTHETIC', json.dumps(self.client.events))
                self.assertNotIn('1234567890', json.dumps(self.client.events))

    def test_simple_null_empty_missing_and_unknown_date_are_distinct(self):
        for kind in SIMPLE_TYPES:
            for value in ({'responseCode': '000'}, {'responseCode': '000', 'paymentList': None},
                          {'responseCode': '000', 'paymentList': []}):
                result = normalize_pages(value, kind)
                self.assertTrue(result['app_success'])
                self.assertEqual(result['complete'], value.get('paymentList') == [])
                self.assertEqual(result['bills'], value.get('paymentList'))
            result = normalize_pages({'responseCode': '000', 'paymentList': [None, {'payLimitDate': 'unknown'}]}, kind)
            from datetime import date
            filtered = due_bills(result, today=date(2026, 10, 1), within_days=7)
            self.assertTrue(filtered['app_success'])
            self.assertEqual(len(filtered['unparsed_bills']), 2)

    def test_partial_pages_and_processing_errors_keep_success(self):
        search = self.prepare('employ')
        def response(fields):
            return dict(responseCode='000', paymentList=[{'payMny': '1'}],
                        pageNaviMap=dict(currentPage='1', totalPage='2', totalCount='2')) if fields['page'] == ['1'] else dict(responseCode='301')
        self.reply('employ.list', response)
        value = collect_bills(self.client, 'employ', search=search)
        self.assertTrue(value['app_success'])
        self.assertEqual(value['service_decision'], 'partial_success')
        self.assertEqual(len(value['bills']), 1)
        self.assertFalse(self.session.active)
        self.assertEqual(len(self.calls), 2)

    def test_giro_direct_input_and_rejection_do_not_continue(self):
        search = self.prepare('giro')
        for response in ({'responseCode': '000', 'searchPayYn': 'N'}, {'responseCode': '311'}):
            self.calls.clear(); self.reply('giro.lookup', response)
            value = collect_bills(self.client, 'giro', search=search)
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(value['app_success'], response['responseCode'] == '000')
            self.assertIsNone(value['bills'])

    def test_summary_busy_day_failure_fallback_and_child_codes(self):
        self.reply('integrated.initialize', {'responseCode': '000', 'busyDayYn': 'Y'})
        result = collect_summary(self.client)
        self.assertIsNone(result['app_success'])
        self.assertEqual(result['next_action'], 'integrated_busy_day')
        self.assertTrue(result['preparation_response']['app_success'])
        self.assertEqual(len(self.calls), 1)
        for initial in ({'responseCode': '000', 'searchNoList': ['SYNTHETIC-IDENTITY'], 'busyDayYn': 'N'}, {'responseCode': '999'}):
            self.reply('integrated.initialize', initial)
            self.reply('integrated.summary', {'responseCode': '000', 'nts': {'count': 1, 'amount': '2000', 'respCode': '000'},
                'traffic': {'count': None, 'respCode': '999'}})
            value = collect_summary(self.client)
            self.assertTrue(value['app_success'])
            categories = {r['tax_type']: r['summary'] for r in value['categories']}
            self.assertEqual(categories['national']['count'], '1')
            self.assertEqual(categories['traffic']['respCode'], '999')
            self.assertIsNone(categories['local'])
            self.assertNotIn('SYNTHETIC-IDENTITY', json.dumps(value))
            self.assertEqual(self.calls[-1][1]['juminNo'], [''])

    def test_plans_and_invalid_input_never_open_session(self):
        with patch('giro.query_flow.SessionStore', side_effect=AssertionError('no store')):
            for kind in BILL_TYPES:
                self.assertTrue(list_bills(kind)['plan_only'])
            for argv in (['bills', 'types'], ['bills', 'summary'], ['bills', 'show', '--type', 'water'],
                         ['bills', 'list', '--type', 'tv']):
                result, code = run(parser().parse_args(argv))
                self.assertEqual(code, 0)
                self.assertFalse(result['network_used'])
        with self.assertRaises(GiroError): collect_bills(self.client, 'water')
        with self.assertRaises(GiroError): collect_bills(self.client, 'kepco', search={'pin': 'SECRET'})
        self.assertEqual(self.calls, [])

    def test_number_query_does_not_need_registered_uid(self):
        self.session.info = {}
        result = collect_bills(self.client, 'social', search=self.prepare('social'))
        self.assertTrue(result['app_success'])
        self.assertEqual(collect_bills(self.client, 'traffic')['next_action'], 'identity_registration_required')

    def test_giro_next_page_stays_unconfirmed_without_inventing_a_request(self):
        search = self.prepare('giro')
        self.reply('giro.list', dict(responseCode='000', paymentList=[{'napbuMny': '1'}],
            pageNaviMap=dict(currentPage='1', totalPage='2', totalCount='2')))
        result = collect_bills(self.client, 'giro', search=search)
        self.assertTrue(result['app_success'])
        self.assertFalse(result['complete'])
        self.assertIn('giro_next_page_unavailable', result['processing_issues'])
        self.assertEqual(len(self.calls), 2, 'lookup then first list only')
