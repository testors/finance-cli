// Original page functions drive requests, validation, SSO and response handling.
// This host supplies CLI inputs and observes results; it never runs Android code.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {loadDOM} from './browserless.mjs';
import {openSavedSession, openSessionPage, SESSION_URL} from './session.mjs';
import {coordinateCommonScreenStartup} from './startup.mjs';
import {INVOICE_PAGES, invoiceQuery, invoicePrepare} from './invoice.mjs';
import {invoiceIssue, issuanceResult} from './invoice_issue.mjs';
import {invoiceAmend} from './invoice_amend.mjs';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export const PP = 'https://mob.hometax.go.kr';
export const HT = 'https://mob.tbht.hometax.go.kr';
const clone = value => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
export const TAX_PAGES = {
  dues:{screen:'UTBRMAAC01F001',menu:'8002010100',cert:'01',title:'납부할세액조회납부',
    action:'ATERMAAA004R01',list:'pubcRomCmnDVOList',automatic:true,localPages:true,
    // With nothing due the service answers success without the list field (observed with amtSum 0).
    emptyOmitsList:response => !response?.amtSum},
  payments:{screen:'UTBRMAAC09F001',menu:'8002020200',cert:'01',title:'납부내역조회',
    action:'ATERMAAA001R01',list:'rspSpclSVOList',start:'pmtDtStrt',end:'pmtDtEnd'},
  refunds:{screen:'UTBRDAAA02F001',menu:'8002030200',cert:'03',title:'환급금상세조회',
    action:'ATERDAAA001R03',list:'unpdNtltxRfamtBrkdSVOList',start:'inqrDtStrt',end:'inqrDtEnd'},
  notices:{screen:'UTBNFAAA51F001',menu:'8002040100',cert:'03',userCert:'null',title:'전자고지열람',
    action:'ATENFAAA001R10',list:'ntfCmnDVOList',start:'pmtDdtStrt',end:'pmtDdtEnd',automatic:true,localPages:true},
};
export const RETURN_MENUS = {'10':'8001032400','14':'8001060400','22':'8001041300',
  '31':'8001050200','32':'8001080500','33':'8001071200','41':'8001021300',
  '43':'8001110500','45':'8001120500','46':'8001100400','47':'8001091000',
  '57':'8001130300','59':'8001150300','65':'8001140700','66':'8001140700'};
export const RETURN_PAGES = {
  list:{screen:'UTBRNAAZ31F001',menu:RETURN_MENUS['10'],cert:'03',userCert:'null',title:'신고내역조회',
    action:'ATERNABA016R01',list:'rtnBscAdmDVOList',next:'pglNavi_onClick'},
  status:{screen:'UTBRNAAZ14F001',menu:'8001010600',cert:'03',userCert:'null',title:'전자신고결과조회',
    action:'ATERNABA016R14',list:'rtnBscAdmDVOList'},
};

// callServer and the analyzed business callbacks use this exact loose equality.
// Missing RESULT throws in the original, so it is unobserved rather than an
// invented server rejection. Additional fields and missing code are accepted.
export function serviceBranch(response) {
  try {return response.RESULT.result == 'S' ? 'success' : 'failure';}
  catch (_) {return 'no_action';}
}

export class BusinessRuntime {
  constructor(config, dependencies = {}) {
    this.config = config;
    this.dependencies = dependencies;
    this.services = [];
    this.pending = 0;
    this.changedAt = Date.now();
    this.warnings = [];
    this.storageByOrigin = {};
    this.navigation = undefined;
    this.nativeRequests = [];
    this.reportPages = [];
    this.popupInputs = {};
    this.targetChecks = [];
    this.targetVerified = false;
    this.timings = [];
  }

  get window() {return this.page?.dom?.window;}

  observer(window) {
    loadDOM().captureNavigation(window, request => {this.navigation = request;});
    window.document.addEventListener('DOMContentLoaded', () => {
      const $ = window.$;
      if (!$?.ajax) return;
      const native = window.nts_callNative;
      window.nts_callNative = (id,data) => {
        // This is our native host boundary, not an Android implementation.
        if (id === 'IN_OPEN_URL') this.nativeRequests.push({action:id,data:clone(data)});
        return native?.call(window,id,data);
      };
      const ajax = $.ajax;
      $.ajax = (...args) => {
        const settings = typeof args[0] === 'object' ? args[0] : {...args[1], url:args[0]};
        const url = new URL(settings.url || window.location.href, window.location.href);
        const action = url.pathname === '/jsonAction.do' ? url.searchParams.get('actionId') : null;
        const service = action?.startsWith('A') ? {action_id:action, branch:'no_action',
          origin:url.origin, response_observed:false, callback_completed:false} : undefined;
        const started = performance.now();
        if (service) this.services.push(service);
        this.pending++;
        const success = settings.success, error = settings.error, complete = settings.complete;
        const host = this;
        let finished = false;
        const finish = () => {
          if (!finished) {finished = true; host.pending--; host.changedAt = Date.now();}
        };
        try {return ajax.call($, {...settings,
          success(response) {
            if (service) {
              service.response_ms = Math.round(performance.now() - started);
              service.response_observed = true;
              service.branch = serviceBranch(response);
              service.response = clone(response);
            }
            try {
              const value = success?.apply(this, arguments);
              if (service) service.callback_completed = true;
              return value;
            } catch (error) {
              if (service) service.callback_exception = true;
              host.warnings.push('서비스 응답 이후 콜백에 오류가 있습니다. 이미 확인한 판정은 유지합니다.');
              // jQuery 1.7 does not reach complete when its callback throws.
              // The response has arrived; finish only our host bookkeeping.
              finish();
              throw error;
            }
          },
          error() {
            if (service) {service.transport_error = true; service.response_ms = Math.round(performance.now() - started);}
            try {return error?.apply(this, arguments);}
            catch (error) {finish(); throw error;}
          },
          complete() {
            finish();
            return complete?.apply(this, arguments);
          },
        });} catch (error) {finish(); throw error;}
      };
      const loadPage = $.mobile.loadPage;
      $.mobile.loadPage = (...args) => {
        const deferred = loadPage.apply($.mobile, args);
        const action = new URL(String(args[0]), window.location.href).searchParams.get('actionId');
        deferred.done(() => this.popupInputs[action]?.(window));
        return deferred;
      };
      Object.assign($.mobile.loadPage, loadPage);
      coordinateCommonScreenStartup(window);
    }, true);
  }

  options() {
    return {...this.dependencies, beforeParse:window => {
      this.observer(window);
      this.dependencies.beforeParse?.(window);
    }};
  }

  async open() {
    this.page = await openSavedSession(this.config, this.options());
    this.storageByOrigin = this.page.storageByOrigin || {};
    await this.settle();
    return this;
  }

  async timed(stage, action) {
    const start = performance.now();
    try {return await action();}
    finally {this.timings.push({stage, duration_ms:Math.round(performance.now() - start)});}
  }

  async ensureTarget(target) {
    const account = this.account();
    this.targetChecks.push({operation:'account.show', branch:'success', reason:'verified_session'});
    const wanted = target.tin === 'ORIGIN' ? (account.rprsTin === '' ? account.tin : account.rprsTin) : target.tin;
    if (!account.tin || !wanted) return false;
    if (account.tin !== wanted) {
      let selected;
      try {
        selected = await this.timed('business.select', () => this.businessSelect(target.kind === 'personal' ? 'ORIGIN' : wanted));
      } finally {
        const service = this.last('ATXPPAAA003A01');
        this.targetChecks.push({operation:'business.select', branch:selected?.branch || service?.branch || 'no_action',
          reason:selected?.reason || (service ? 'original_service_result' : 'original_action_not_observed')});
      }
      if (selected.branch !== 'success' || selected.data?.account?.tin !== wanted || !this.ready) return false;
    }
    this.confirmedTarget = {tin:wanted};
    this.targetVerified = true;
    return true;
  }

  snapshot() {
    if (this.window) this.storageByOrigin[this.window.location.origin] = {
      sessionStorage:{...this.window.sessionStorage}, localStorage:{...this.window.localStorage},
    };
  }

  async navigate(request) {
    this.snapshot();
    const referrer = this.window.location.href;
    const jar = this.page.jar;
    this.page.close();
    this.pending = 0;
    this.navigation = undefined;
    this.page = await openSessionPage({url:request.url, jar,
      storage:this.storageByOrigin[new URL(request.url).origin],
      timeout:this.config.timeout * 1000, referrer, request:{method:request.method, body:request.body}}, this.options());
    await this.settle();
  }

  async until(predicate) {
    const deadline = Date.now() + this.config.timeout * 1000;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      await delay(25);
    }
    return false;
  }

  async settle() {
    if (!await this.until(() => this.pending === 0 && Date.now() - this.changedAt >= 150))
      this.warnings.push('서비스 비동기 후속 처리가 관찰 시간 안에 모두 끝나지 않았습니다.');
  }

  last(action, from = 0) {return this.services.slice(from).findLast(s => s.action_id === action);}

  async invoke(action, fn) {
    const from = this.services.length;
    fn(this.window);
    // Input validation can stop synchronously without a request. Do not invent
    // a failed server response in that case or proceed past its original check.
    await this.until(() => this.last(action, from)?.response_observed ||
      this.last(action, from)?.transport_error ||
      (!this.last(action, from) && this.window.document.getElementById('popup_container')));
    await this.settle();
    return this.last(action, from);
  }

  get ready() {return this.page?.state.branch === 'success' && this.page.pageReady;}

  account() {
    const keys = ['userId','userNm','tin','pubcUserNo','txprDscmNo','userClsfCd','txprClsfCd',
      'lgnCertCd','userCertClCd','lgnUserClCd','ntplAthYn','ntplBmanAthYn','crpBmanAthYn',
      'txaaYn','dprtUserYn','txpAgnYn','ssnAltPsbYn','smprYn','rprsTin','cnvrTin'];
    return Object.fromEntries(keys.map(key => [key, this.window.ntsframework.session.get(key)]));
  }

  async businessList(status) {
    const w = this.window, s = w.ntsframework.session;
    let originTin = s.get('rprsTin');
    if (originTin === '') originTin = s.get('tin');
    // Header fnHeader_initAsidePfbCnr1: preserve the source's loose comparisons.
    if (s.get('ssnAltPsbYn') != 'Y' ||
        (s.get('smprYn') == 'Y' && s.get('tin') != originTin))
      return {branch:'no_action', reason:'business_switch_unavailable'};
    this.popupInputs.UTBPPBAA04F001 = window => {
      // The original popup marks value 2 (계속사업자) selected in its HTML.
      window.$('#selectPfbStat').val(status === undefined ? '2' : status);
    };
    const service = await this.invoke('ATXPPAAA003R01', window => window.nts_busnSct());
    return this.result(service, {items:clone(w.searchResultList),
      source_items:clone(service?.response?.bmanBscInfrInqrDVOList),
      status:w.$('#selectPfbStat option:selected').text()});
  }

  async businessSelect(tin) {
    const listing = await this.businessList('1');
    if (listing.branch !== 'success') return listing;
    const w = this.window;
    if (tin !== 'ORIGIN' && !listing.data?.source_items?.some(item => item.tin == tin))
      return {branch:'no_action', reason:'business_not_in_original_list', data:listing.data};
    const service = await this.invoke('ATXPPAAA003A01', window => {
      window.btnProcess_onClick(tin);
      // The explicit select command is the user's selection and confirmation.
      // Click only this source dialog; never auto-confirm unrelated prompts.
      const message = window.$('#popup_message').text();
      if (message.includes('개인으로 전환됩니다.') || message.includes('선택한 사업장으로 전환됩니다.'))
        window.$('#popup_ok').trigger('click');
    });
    if (service?.branch === 'success') {
      if (w.$('#popup_message').text().includes('전환이 완료')) w.$('#popup_ok').trigger('click');
      await this.until(() => this.navigation || w.document.getElementById('layer_pop_UTBMPAAA15'));
      if (this.navigation && new URL(this.navigation.url).searchParams.get('actionId') === 'UTBPPZAA01F001') {
        await this.navigate(this.navigation);
        if (!this.ready) this.warnings.push('서비스 사업장 전환은 성공했습니다. 후속 메인 세션 확인은 완료되지 않았습니다.');
      } else this.warnings.push('서비스 전환은 성공했습니다. 후속 추가인증 또는 메인 이동이 완료되지 않았습니다.');
    }
    return this.result(service, {account:this.account()});
  }

  async menu(entry) {
    this.navigation = undefined;
    const service = entry.server || 'HT';
    const origin = this.window.ntsframework.session.get(service.toLowerCase()+'server');
    const url = origin+'/jsonAction.do?actionId='+entry.screen;
    this.window.nts_menuOpenPageJump(url, service, entry.cert, entry.userCert ?? '10', 'N', entry.menu, entry.title);
    await this.settle();
    if (!this.navigation || new URL(this.navigation.url).searchParams.get('actionId') !== entry.screen)
      return false;
    await this.navigate(this.navigation);
    return this.ready;
  }

  setValue(id, value) {
    if (value !== undefined) this.window.$('#'+id).val(value);
  }

  setDate(id, value) {
    if (value !== undefined) this.setValue(id, /^\d{8}$/.test(value)
      ? value.slice(0,4)+'-'+value.slice(4,6)+'-'+value.slice(6) : value);
  }

  setRadio(name, value) {
    if (value === undefined) return;
    this.window.$('input[name="'+name+'"]').each(function () {this.checked = this.value == value;});
  }

  unavailable() {
    return {branch:this.page.state.branch === 'failure' ? 'failure' : 'no_action',
      reason:this.page.state.branch === 'success' ? 'original_page_not_ready' : this.page.state.reason};
  }

  async tax(operation) {
    const entry = TAX_PAGES[operation], config = this.config;
    const from = this.services.length;
    if (!await this.menu(entry)) return this.unavailable();
    if (operation === 'dues') {
      this.navigation = undefined;
      this.window.btnProcess_onClick();
      await this.until(() => this.navigation || this.window.document.getElementById('popup_container'));
      if (new URL(this.navigation?.url || this.window.location.href).searchParams.get('actionId') !== 'UTBRMAAC02F001')
        return {branch:'no_action', reason:'original_dues_navigation_not_observed'};
      await this.navigate(this.navigation);
      if (!this.ready) return this.unavailable();
    }
    const w = this.window;
    this.setDate(entry.start, config.from);
    this.setDate(entry.end, config.to);
    if (operation === 'payments') this.setRadio('rdoInqr', config.payment_type);
    if (operation === 'refunds') this.setValue('selectInqrClCd', config.refund_status);
    if (operation === 'notices') {
      this.setRadio('elctNtfCl', config.notice_type);
      this.setValue('prslClCd', config.read_status);
      this.setValue('itrfCd', config.tax_code);
    }
    const customized = ['from','to','payment_type','refund_status','notice_type','read_status','tax_code']
      .some(key => config[key] !== undefined && config[key] !== null);
    let service = this.last(entry.action, from);
    if (!entry.automatic || customized) service = await this.invoke(entry.action, window => {
      // Payments' click handler enforces the original department-user condition.
      if (operation === 'payments') window.$('button[id=btnSearch]').trigger('click');
      else window.btnSearch_onClick();
    });
    return this.collectPages(entry, service);
  }

  async collectPages(entry, service, {locate} = {}) {
    const config = this.config, pages = [];
    const pagination = {requested_all:Boolean(config.all_pages), complete:false};
    const next = page => this.invoke(entry.action, window => window[entry.next || 'pgMoreView_onClick'](page));
    const add = item => {
      if (item?.response_observed) {
        pages.push({branch:item.branch,items:clone(item.response?.[entry.list]),
          page_info:clone(item.response?.pageInfoVO)});
        const list = item.response?.[entry.list];
        if (item.branch === 'success' && !Array.isArray(list) && !(list == null && entry.emptyOmitsList?.(item.response)))
          this.warnings.push('서비스는 성공으로 판정했습니다. 목록 형식이 예상과 달라 서비스 응답도 함께 보존합니다.');
      }
    };
    add(service);
    if (!entry.localPages && config.page !== undefined && config.page != 1 && service?.branch === 'success') {
      const following = await next(config.page);
      if (!following?.response_observed) {
        this.warnings.push('요청한 페이지의 서비스 응답을 확인하지 못했습니다. 앞서 받은 결과를 보존합니다.');
        pagination.reason = 'requested_page_unobserved';
      } else {service = following; pages.length = 0; add(service);}
    }
    if (!entry.localPages && (config.all_pages || locate !== undefined) && !pagination.reason) {
      const seenPages = new Set();
      while (service?.branch === 'success') {
        if (locate !== undefined && service.response?.[entry.list]?.some(item=>item.rtnCvaId == locate)) {
          pagination.complete = true; pagination.reason = 'requested_return_found'; break;
        }
        const info = service.response?.pageInfoVO;
        const page = Number(info?.pageNum), size = Number(info?.pageSize), total = Number(info?.totalCount);
        if (!Number.isFinite(page) || !Number.isFinite(size) || !Number.isFinite(total) || size <= 0 || seenPages.has(page)) {
          this.warnings.push('서비스 페이지 정보로 다음 페이지를 결정할 수 없습니다. 받은 성공 결과를 보존합니다.');
          pagination.reason = 'unusable_page_info';
          break;
        }
        if (page * size >= total) {pagination.complete = true; break;}
        seenPages.add(page);
        const following = await next(page + 1);
        if (!following?.response_observed) {
          pagination.reason = 'next_page_unobserved';
          this.warnings.push('다음 페이지의 서비스 응답을 확인하지 못했습니다. 받은 성공 결과를 보존합니다.');
          break;
        }
        service = following;
        add(service);
      }
    }
    if ((entry.localPages || (!config.all_pages && locate === undefined)) && !pagination.reason)
      pagination.complete = service?.branch === 'success';
    if (service?.branch !== 'success') pagination.reason ||= 'original_result_not_success';
    const accepted = pages.filter(page=>page.branch === 'success');
    return this.result(service, {items:accepted.length === 1 ? accepted[0].items : accepted.flatMap(page => page.items || []),
      pages,pagination,source:clone(service?.response),account:this.account()});
  }

  async returns(operation, {returnId} = {}) {
    const config = this.config;
    if (operation === 'forms' && config.query_source === 'status') {
      const listing=await this.returns('status',{returnId:config.return_id});
      if (listing.branch !== 'success') return listing;
      const row=this.selectedReturn(listing);
      if (!row) return {branch:'no_action',reason:'requested_return_not_found',data:listing.data};
      if (!await this.enterReturnContext(row)) return this.unavailable();
      const detail=await this.invoke('ATERNABA016R02',w=>w.nts_openPopup('UTBRNAAZ32F001',{param:{rtnCvaId:row.rtnCvaId}}));
      return this.result(detail,{items:clone(detail?.response?.rtnBscAdmDVOList),return:clone(row),
        source:clone(detail?.response),account:this.account(),query:listing});
    }
    const entry = {...RETURN_PAGES[operation === 'status' ? 'status' : 'list']};
    if (operation !== 'status' && RETURN_MENUS[config.tax_code]) entry.menu = RETURN_MENUS[config.tax_code];
    if (!await this.menu(entry)) return this.unavailable();
    const w = this.window;
    // Both original pages initialize the Z04 common selector asynchronously.
    await this.until(() => w.document.querySelector('#UTBRNAAZ04_bsnoResnoSelect option'));
    await this.settle();
    if (operation === 'status') {
      this.setValue('itrfCd', config.tax_code);
      this.setValue('inqrDtYr', config.year);
      this.setValue('inqrDtMm', config.month === undefined ? undefined : String(config.month).padStart(2,'0'));
    } else {
      // Known tax codes enter via the original menu mapping, including 66→65.
      // Other supplied values go through the actual select and inputCheck.
      if (config.tax_code !== undefined && !RETURN_MENUS[config.tax_code]) {
        this.setValue('itrfCd_UTBRNAAZ31',config.tax_code);
        w.$('#itrfCd_UTBRNAAZ31').trigger('change');
      }
      this.setDate('rtnDtSrt_UTBRNAAZ31',config.from);
      this.setDate('rtnDtEnd_UTBRNAAZ31',config.to);
      this.setValue('input_DprtUserId_410_UTBRNAAZ31',config.department_user);
      if (config.disclose !== undefined) {
        this.setRadio('ntplInfpYn_UTBRNAAZ31',config.disclose);
        w.$('input[name=ntplInfpYn_UTBRNAAZ31]:checked').trigger('change');
      }
    }
    if (config.taxpayer !== undefined) {
      this.setValue('UTBRNAAZ04_bsnoResnoSelect',config.taxpayer);
      w.$('#UTBRNAAZ04_bsnoResnoSelect').trigger('change');
    }
    const choices = [...w.document.querySelectorAll('#UTBRNAAZ04_bsnoResnoSelect option')]
      .map(option=>({value:option.value,label:option.textContent}));
    const service = await this.invoke(entry.action, window=>window.btnSearch_onClick());
    const listing = await this.collectPages(entry,service,{locate:operation === 'forms' ? config.return_id : returnId});
    listing.data.taxpayer_choices = choices;
    if (operation !== 'forms') return listing;
    if (listing.branch !== 'success') return listing;
    // Original Z31 displays one return per page. Use its real row callback and
    // popup initialization so authorization, mappers and report IDs stay intact.
    if (!w.ttirnam101DVOListDes?.length) return {branch:'no_action',reason:'no_return_selected',data:listing.data};
    if (config.return_id !== undefined && !w.ttirnam101DVOListDes.some(item=>item.rtnCvaId == config.return_id))
      return {branch:'no_action',reason:'requested_return_not_found',data:listing.data};
    const detail = await this.invoke('ATERNABA016R02',window=>window.btnGrid_onCellClick(0,10));
    return this.result(detail,{items:clone(detail?.response?.rtnBscAdmDVOList),
      return:clone(w.ttirnam101DVOListDes),source:clone(detail?.response),account:this.account()});
  }

  selectedReturn(listing) {
    const rows=this.config.query_source === 'status' ? listing.data?.items : this.window.ttirnam101DVOListDes;
    return this.config.return_id === undefined ? rows?.[0] : rows?.find(row=>row.rtnCvaId == this.config.return_id);
  }

  async enterReturnContext(row) {
    // Z14 returns the taxpayer's filings, including another submitter's records.
    // Z31 queries the current submitter. Do not fabricate a Z31 row to bridge
    // these lists: use the shared receipt function with an actual Z14 result.
    // Enter Z31 normally to initialize its original report/audit globals.
    const entry = {...RETURN_PAGES.list};
    if (RETURN_MENUS[row.itrfCd]) entry.menu = RETURN_MENUS[row.itrfCd];
    return this.menu(entry);
  }

  async prepareReceiptFromStatus(row, options = {}) {
    return this.prepareReportFromStatus(row,'receipt',options);
  }

  async prepareReportFromStatus(row, kind = 'receipt', {disclose} = {}) {
    if (!await this.enterReturnContext(row)) return undefined;
    const w = this.window, from = this.nativeRequests.length;
    if (kind === 'detail') {
      // Z31:803 has this preview exclusion before its shared popup call.
      if (row.itrfCd == '46' && ['E45','E46','E47','E48'].includes(row.stmnKndCd)) return undefined;
      const forms=await this.invoke('ATTRNZZZ020R01',window=>window.rnCm_openPopupStmnLdgrInqr({
        itrfCd:row.itrfCd,rtnCvaId:row.rtnCvaId,
        bsafClCd:window.ntsframework.object.get("map[@id='resParam_UTBRNAAZ31']/bsafClCd"),rptInqrCl:'11'}));
      return this.finishReportDetail(forms,from,disclose);
    }
    this.setRadio('ntplInfpYn_UTBRNAAZ31',disclose);
    w.rnCm_rtnTfrPrint({itrfCd:row.itrfCd,rtnCvaId:row.rtnCvaId,
      ntplInfpYn:w.$('input[name=ntplInfpYn_UTBRNAAZ31]:checked').val()});
    return this.captureReportNavigation(from);
  }

  async prepareReportRequest(kind = 'receipt', {disclose} = {}) {
    const from = this.nativeRequests.length;
    if (kind === 'detail') {
      const forms = await this.invoke('ATTRNZZZ020R01',window=>window.btnGrid_onCellClick(0,9));
      return this.finishReportDetail(forms,from,disclose);
    } else this.window.btnGrid_onCellClick(0,11);
    return this.captureReportNavigation(from);
  }

  async finishReportDetail(forms, from, disclose) {
    if (forms?.branch !== 'success') return undefined;
    await this.until(() => this.window.document.querySelector('input[name=ntplInfpYn_UTBRNAAZ39]') ||
      this.nativeRequests.length > from);
    if (this.window.document.querySelector('input[name=ntplInfpYn_UTBRNAAZ39]')) {
      this.setRadio('ntplInfpYn_UTBRNAAZ39',disclose);
      const applied=await this.invoke('ATTRNZZZ020A01',window=>window.btnAppl_onClick());
      if (applied?.branch !== 'success') return undefined;
    }
    return this.captureReportNavigation(from);
  }

  reportForms() {
    return [...this.window.document.querySelectorAll('#UTBRNAAZ34_listview table tbody tr.mob_ex')]
      .map(row=>Object.fromEntries([...row.querySelectorAll('td[name]')].map(cell=>[cell.getAttribute('name'),cell.textContent])));
  }

  async nextReportPage(page) {
    const from = this.nativeRequests.length;
    this.window.rptDataPageNavi_onclick(page);
    return this.captureReportNavigation(from);
  }

  async selectReportForm(formCode) {
    const rows = [...this.window.document.querySelectorAll('#UTBRNAAZ34_listview table tbody tr')];
    const row = rows.find(item=>item.querySelector('td[name=frmlCd]')?.textContent == formCode);
    if (!row) return undefined;
    const from = this.nativeRequests.length;
    this.window.fn_txtFrmlOnClick(row.id.split('_mob_ex_').at(-1));
    return this.captureReportNavigation(from);
  }

  async captureReportNavigation(from) {
    await this.until(() => this.nativeRequests.length > from);
    const request = this.nativeRequests.slice(from).find(item=>{
      const url = new URL(item.data?.url || '',this.window.location.href);
      return url.origin === this.window.location.origin && url.searchParams.get('actionId') === 'UTBPPZAA07F001';
    });
    if (!request) return undefined;
    // MainActivity IN_OPEN_URL starts OtherSystemActivity, retaining the main
    // WebView. Its new WebView has separate sessionStorage and the same origin's
    // localStorage. Keep the parent alive for further forms/data-page requests.
    const child = new BusinessRuntime(this.config, this.dependencies);
    try {
      child.page = await openSessionPage({url:request.data.url, jar:this.page.jar,
        storageParent:this.window, timeout:this.config.timeout * 1000}, child.options());
      await child.settle();
      await child.until(() => child.navigation);
      const navigation = child.navigation;
      if (navigation?.method !== 'POST' || navigation.url !== 'https://sesw.hometax.go.kr/serp/clipreport.do')
        return undefined;
      return {...clone(navigation),referrer:child.window.location.href};
    } finally {
      if (child.page) {
        const record = child.page.record('report');
        this.reportPages.push({session_validation:{...child.page.state},page_ready:child.page.pageReady,
          runtime_issues:record.runtime_issues,warnings:record.warnings});
        this.warnings.push(...record.warnings);
      }
      this.services.push(...child.services);
      this.warnings.push(...child.warnings);
      child.close();
    }
  }

  result(service, data) {
    const message = this.window?.document.getElementById('popup_message')?.textContent;
    return {branch:service?.branch || 'no_action', reason:service ? 'original_service_result' : 'original_action_not_observed',
      ...(service ? {action_id:service.action_id} : {}), data,
      // Source notices can contain taxpayer information: private artifact only.
      ...(message ? {original_dialog:{message}} : {})};
  }

  record(result) {
    this.snapshot();
    this.page.storageByOrigin = this.storageByOrigin;
    const session = this.page.record('business');
    return {...session, scope:'browserless_business', operation:this.config.command+'.'+this.config.operation,
      session_validation:{...this.page.state}, ...result,
      common_screen_startup:clone(this.window?.__hometaxCommonStartup),
      services:this.services, report_pages:this.reportPages, warnings:[...session.warnings, ...this.warnings]};
  }

  close() {this.page?.close();}
}

export async function runBusiness(config, dependencies = {}) {
  if (!Number.isSafeInteger(Math.ceil(config.timeout * 1000)) || config.timeout <= 0)
    throw new Error('Invalid timeout');
  if (config.target && (config.command !== 'tax' || !['personal','business'].includes(config.target.kind) ||
      typeof config.target.tin !== 'string' || !config.target.tin.trim())) throw new Error('Invalid target');
  const output = await fs.open(config.output, 'wx', 0o600);
  const runtime = new BusinessRuntime(config, dependencies);
  let result = {branch:'no_action', reason:'unobserved'}, record;
  try {
    await runtime.timed('session.open', () => runtime.open());
    if (runtime.ready) {
      if (config.command === 'account' && config.operation === 'show') {
        if (config.domain === 'ht' && !await runtime.menu(TAX_PAGES.payments)) result = runtime.unavailable();
        else result = {branch:'success', reason:'verified_session', data:{account:runtime.account()}};
      }
      else if (config.command === 'business' && config.operation === 'list')
        result = await runtime.businessList(config.status);
      else if (config.command === 'business' && config.operation === 'select')
        result = await runtime.businessSelect(config.tin);
      else if (config.command === 'tax' && TAX_PAGES[config.operation]) {
        if (config.target && !await runtime.ensureTarget(config.target))
          result = {branch:'no_action', reason:'target_unverified', data:{account:runtime.account()}};
        else result = await runtime.timed('tax.'+config.operation, () => runtime.tax(config.operation));
      }
      else if (config.command === 'returns' && ['list','status','forms'].includes(config.operation))
        result = await runtime.returns(config.operation);
      else if (config.command === 'invoice' && INVOICE_PAGES[config.operation])
        result = await invoiceQuery(runtime);
      else if (config.command === 'invoice' && config.operation === 'prepare')
        result = await invoicePrepare(runtime,JSON.parse(await fs.readFile(config.input,'utf8')));
      else if (config.command === 'invoice' && config.operation === 'amend')
        result = await invoiceAmend(runtime,config.input ? JSON.parse(await fs.readFile(config.input,'utf8')) : {});
      else if (config.command === 'invoice' && config.operation === 'issue')
        result = await invoiceIssue(runtime);
      else throw new Error('Unsupported business command');
    } else result = runtime.unavailable();
  } catch (error) {
    dependencies.onError?.(error);
    // A final service result observed before a host exception remains valid.
    const finalAction = config.command === 'business'
      ? (config.operation === 'select' ? 'ATXPPAAA003A01' : 'ATXPPAAA003R01')
      : config.command === 'returns' ? (config.operation === 'forms' ? 'ATERNABA016R02' : RETURN_PAGES[config.operation]?.action)
        : config.command === 'invoice' ? INVOICE_PAGES[config.operation]?.action : TAX_PAGES[config.operation]?.action;
    const finalService = runtime.services.findLast(s => s.response_observed && s.action_id === finalAction);
    if (finalService) result = runtime.result(finalService,{source:clone(finalService.response)});
    if (config.command === 'invoice' && config.operation === 'issue') result=issuanceResult(runtime);
    runtime.warnings.push('업무 실행의 후속 처리 중 오류가 있습니다. 관찰한 서비스 판정은 유지합니다.');
  } finally {
    try {
      record = runtime.page ? runtime.record(result) : {scope:'browserless_business',
        operation:config.command+'.'+config.operation,...result, warnings:runtime.warnings};
      Object.assign(record, {timings:runtime.timings}, config.target ? {
        target_verified:runtime.targetVerified, target_check:runtime.targetChecks,
        confirmed_target:runtime.confirmedTarget} : {});
      record.session_file_saved = true;
      await output.writeFile(JSON.stringify(record, null, 2));
    } catch (_) {
      record ||= {...result, warnings:[]};
      record.session_file_saved = false;
      record.warnings.push('결과·세션 파일 저장을 완료하지 못했습니다. 서비스 판정은 유지합니다.');
    }
    try {runtime.close();}
    catch (_) {record.warnings.push('DOM 정리 중 오류가 있습니다. 서비스 판정은 유지합니다.');}
    try {await output.close();}
    catch (_) {
      record.session_file_saved = false;
      record.warnings.push('결과·세션 파일 닫기에 실패했습니다. 서비스 판정은 유지합니다.');
    }
  }
  return {scope:record.scope, operation:record.operation, branch:record.branch, reason:record.reason,
    action_id:record.action_id, session_file_saved:record.session_file_saved,
    ...(config.target ? {target_verified:runtime.targetVerified, target_check:runtime.targetChecks} : {}),
    ...(config.timings ? {timings:runtime.timings} : {}),
    item_count:Array.isArray(record.data?.items) ? record.data.items.length : undefined,
    warnings:record.warnings};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;
    const result = await runBusiness(JSON.parse(input));
    for (const warning of result.warnings) process.stderr.write('warning: '+warning+'\n');
    const {warnings, ...summary} = result;
    process.stdout.write(JSON.stringify({...summary, warning_count:warnings.length})+'\n');
    process.exitCode = result.branch === 'success' ? 0 : result.branch === 'failure' ? 1 : 3;
  } catch (error) {
    process.stderr.write('error: 업무 CLI 입력 또는 저장 경로 오류 ('+error.constructor.name+')\n');
    process.exitCode = 2;
  }
}
