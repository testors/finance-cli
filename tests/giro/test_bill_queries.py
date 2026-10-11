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
from giro.query_flow import collect_bills, collect_detail, collect_regions, collect_summary, list_bills
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

    def test_summary_reads_local_tax_and_the_three_sums_from_their_own_fields(self):
        self.reply('integrated.initialize', {'responseCode': '000', 'busyDayYn': 'N'})
        self.reply('integrated.summary', {'responseCode': '000',
            'local': {'count': '1', 'amount': '1000', 'respCode': '000'},
            'localtax': {'count': '3', 'amount': '6000', 'respCode': '000'},
            'ntax': {'count': '-1'}, 'total': {'count': '3', 'amount': '-2', 'respCode': '000'}})
        value = collect_summary(self.client)
        categories = {r['tax_type']: r['summary'] for r in value['categories']}
        self.assertEqual(categories['local'], {'count': '1', 'amount': '1000', 'respCode': '000'})
        self.assertEqual(value['totals']['localtax']['count'], '3', 'the sum of local revenue is not the local tax item')
        self.assertEqual(value['totals']['ntax']['count'], '-1')
        self.assertEqual(value['totals']['total']['amount'], '-2')
        self.assertEqual(set(value['totals']), {'localtax', 'ntax', 'total'})

    def regions(self, kind):
        self.reply(kind+'.provinces', dict(responseCode='000', provinceList=[
            dict(areaCode='01', areaName='합성시'), None, dict(areaCode='02', areaName='합성도')]))
        self.reply(kind+'.districts', lambda fields: dict(responseCode='000', districtList=[
            dict(sortCode=fields['areaCode'][0]+'1', giroNo='1000001', sigunguName='합성구'),
            dict(sortCode=fields['areaCode'][0]+'2', giroNo='1000002', sigunguName='합성군')]))

    def test_regions_list_provinces_and_the_districts_of_the_first_or_the_named_province(self):
        for kind in REGION_TYPES:
            with self.subTest(kind=kind):
                self.calls.clear(); self.regions(kind)
                value = collect_regions(self.client, kind)
                self.assertTrue(value['app_success'], value)
                self.assertEqual(value['provinces'], [dict(area_code='01', name='합성시'), None, dict(area_code='02', name='합성도')])
                self.assertEqual(value['area_code'], '01')
                self.assertEqual(value['districts'][1], dict(district_code='012', district_giro_no='1000002', name='합성군'))
                self.assertEqual([path for path, _ in self.calls], [ENDPOINTS[kind+'.provinces'].path, ENDPOINTS[kind+'.districts'].path])
                self.assertEqual(self.calls[1][1]['areaCode'], ['01'])
                if kind == 'nontax': self.assertTrue(all(fields.get('tongYn') == ['Y'] for _, fields in self.calls))
                value = collect_regions(self.client, kind, '02')
                self.assertEqual((value['area_code'], value['districts'][0]['district_code']), ('02', '021'))
                self.assertEqual(self.calls[-1][1]['areaCode'], ['02'])
                self.assertEqual(len(self.calls), 4, 'no bill is queried')

    def test_regions_keep_what_was_received_and_never_send_an_unlisted_province(self):
        self.regions('local')
        value = collect_regions(self.client, 'local', '99')
        self.assertEqual((value['next_action'], value['districts'], len(value['provinces'])), ('local_region_unavailable', None, 3))
        self.assertEqual(len(self.calls), 1, 'an unlisted province is not asked for')
        self.reply('local.districts', {'responseCode': '999'})
        value = collect_regions(self.client, 'local')
        self.assertEqual((value['service_decision'], value['districts']), ('partial_success', None))
        self.assertEqual(len(value['provinces']), 3)
        self.assertFalse(value['last_request']['app_success'])
        for provinces in ({'responseCode': '000'}, {'responseCode': '000', 'provinceList': []}):
            self.calls.clear(); self.reply('local.provinces', provinces)
            value = collect_regions(self.client, 'local')
            self.assertTrue(value['app_success'])
            self.assertEqual((value['next_action'], value['districts']), ('local_region_unavailable', None))
            self.assertEqual(len(self.calls), 1)
        self.calls.clear(); self.reply('local.provinces', {'responseCode': '999'})
        value = collect_regions(self.client, 'local')
        self.assertEqual((value['app_success'], value['provinces'], len(self.calls)), (False, None, 1))
        for kind, code in (('national', None), ('water', None), ('local', ''), ('local', 1)):
            with self.assertRaises(GiroError): collect_regions(self.client, kind, code)
        self.assertEqual(len(self.calls), 1)

    def test_bill_query_goes_to_the_chosen_district_and_stops_when_it_is_not_listed(self):
        self.prepare('env'); self.regions('env')
        value = collect_bills(self.client, 'env', search=dict(area_code='02', district_code='022', district_giro_no='1000002'))
        self.assertTrue(value['app_success'], value)
        self.assertEqual(value['query_region'], {'province': '합성도', 'district': '합성군'})
        self.assertEqual((self.calls[-1][1]['sortCode'], self.calls[-1][1]['giroNo']), (['022'], ['1000002']))
        self.calls.clear()
        value = collect_bills(self.client, 'env', search=dict(area_code='02', district_code='012'))
        self.assertEqual((value['next_action'], value['bills']), ('local_region_unavailable', None))
        self.assertEqual(len(self.calls), 2, 'the lists were read and no bill was queried')

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
