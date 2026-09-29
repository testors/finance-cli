// ET lookup uses the original page's validation, NetFunnel and callbacks.
export const INVOICE_PAGES = {
  list:{server:'ET',screen:'UTBETGBA01F001',menu:'8006020100',cert:'03',
    title:'전자(세금)계산서목록',action:'ATEETGBA001R01',list:'etxivIsnBrkdTermDVOList'},
  detail:{server:'ET',screen:'UTBETGBA02F001',menu:'8006020200',cert:'03',
    title:'전자(세금)계산서상세',action:'ATEETGBA001R05'},
};
export const ISSUE_ENTRY={server:'ET',screen:'UTBETGAA23F001',menu:'8006010100',cert:'03',
  userCert:'null',title:'전자세금계산서건별발급'};
const clone = value => value === undefined ? undefined : JSON.parse(JSON.stringify(value));

export async function invoiceQuery(runtime) {
  const config = runtime.config, entry = INVOICE_PAGES[config.operation];
  if (!await runtime.menu(entry)) return runtime.unavailable();
  const w = runtime.window;
  // Startup lgnCertChk can display a business-switch/authentication notice.
  // Respect that original gate instead of dispatching a query behind it.
  if (w.document.getElementById('popup_container')) return runtime.result(undefined);
  if (config.operation === 'detail') {
    runtime.setValue('num1',config.approval_number);
    const service = await runtime.invoke(entry.action,w=>w.btnSearch_onClick());
    return runtime.result(service,{invoice:clone(service?.response?.etxivIsnBrkdTermDVO),
      items:clone(service?.response?.lsatInfrBizSVOList),
      settlement:clone(service?.response?.sncClInfrBizSVO),source:clone(service?.response),
      account:runtime.account()});
  }
  runtime.setRadio('rdEtxivClsfCd',config.invoice_type);
  if (config.invoice_type !== undefined) w.rdEtxivClsfCd_onClick();
  runtime.setRadio('rdPrhSlsClCd',config.direction === 'sales' ? '01' : config.direction === 'purchases' ? '02' : config.direction);
  if (config.direction !== undefined) w.rdPrhSlsClCd_onClick();
  runtime.setRadio('selDmnrBsnoClCd',config.counterparty_type);
  if (config.counterparty_type !== undefined) w.selDmnrBsnoClCd_onChange();
  runtime.setDate('inqrDtStrt',config.from);
  runtime.setDate('inqrDtEnd',config.to);
  const type=w.$('input[name=rdEtxivClsfCd]:checked').val();
  for (const [key,id] of Object.entries({date_type:'selDtCl',counterparty_name:'txtTnmNm',
    branch_number:'txtMpbNo',classification:'selEtxivClsfCd'+type,kind:'etxivKndCd'+type,issuance_type:'selIsnTypeCd'}))
    runtime.setValue(id,config[key]);
  if (config.counterparty_number !== undefined) {
    const value=String(config.counterparty_number).replaceAll('-','');
    const business=w.$('input[name=selDmnrBsnoClCd]:checked').val() == '01';
    const ids=business ? ['bsno1','bsno2','bsno3'] : ['jumin1','jumin2'];
    const parts=business ? [value.slice(0,3),value.slice(3,5),value.slice(5)] : [value.slice(0,6),value.slice(6)];
    ids.forEach((id,i)=>runtime.setValue(id,parts[i]));
  }
  const service=await runtime.invoke(entry.action,w=>w.$('#btnSearch').trigger('click'));
  const result=await runtime.collectPages(entry,service);
  if (result.data) result.data.totals=clone(result.data.source?.etxivIsnBrkdTermDVO);
  return result;
}

export function originalDialog(runtime) {
  return runtime.window?.document.getElementById('popup_message')?.textContent || '';
}

// Confirm only the named original navigation dialog. Other notices remain
// visible in the private result and stop the workflow without a fake rejection.
export async function invoiceMove(runtime, act, screen, confirmations=[]) {
  runtime.navigation=undefined;
  try {act(runtime.window);}
  catch (error) {
    // GAC21 dispatches navigation before referring to its commented-out pageId.
    // Retain an observed original transition, never invent one after an error.
    await runtime.settle(); // goPage's session check completes asynchronously.
    if (!runtime.navigation) throw error;
    runtime.warnings.push('서비스 화면 이동 후 스크립트 오류가 있습니다. 관찰한 이동을 유지합니다.');
  }
  for (let count=0;count<=confirmations.length;count++) {
    await runtime.settle();
    if (runtime.navigation) break;
    await runtime.until(()=>runtime.navigation || originalDialog(runtime));
    if (runtime.navigation) break;
    const message=originalDialog(runtime);
    const accepted=confirmations.find(text=>message.includes(text));
    if (!accepted) return false;
    runtime.window.$('#popup_ok').trigger('click');
  }
  if (!runtime.navigation || new URL(runtime.navigation.url).searchParams.get('actionId') !== screen) return false;
  await runtime.navigate(runtime.navigation);
  return runtime.ready;
}

const FORM_FIELDS={name:'txtTxprNm',representative:'txtRprsFnm',address:'txtPfbAdr',
  business_type:'txtBcNm',business_item:'txtItmNm',branch_number:'txtSplrMpbNo'};
export function party(runtime,values={},supplier=false) {
  for (const [key,id] of Object.entries(FORM_FIELDS)) runtime.setValue(id,values[key]);
  for (const [key,ids] of Object.entries(supplier ? {email:['email1','emailTxt']}
    : {email:['memail1','emailTxt1'],secondary_email:['semail1','emailTxt2']})) {
    if (values[key] === undefined) continue;
    const value=String(values[key]),at=value.lastIndexOf('@');
    runtime.setValue(ids[0],at<0 ? value : value.slice(0,at));
    runtime.setValue(ids[1],at<0 ? '' : value.slice(at+1));
  }
}

export function invoiceDraft(runtime,extra=[]) {
  const s=runtime.window.ntsframework.session;
  return Object.fromEntries(['etxivObj','splrInfrBizSVO','dmnrInfrBizSVO','trteInfrBizSVO',
    'lsatInfrBizSVOList','sncClInfrBizSVO','sncInfrBizSVO','flagConfirm_biz','flagConfirm_dmnr',...extra]
    .map(key=>[key,clone(s.get(key))]));
}

export async function invoicePrepare(runtime, input) {
  if (!await runtime.menu(ISSUE_ENTRY)) return runtime.unavailable();
  // The source permits entering a draft with a login-only certificate.
  if (originalDialog(runtime).includes('로그인한 인증서는 전자(세금)계산서 발급용 인증서가 아닙니다.'))
    runtime.window.$('#popup_ok').trigger('click');
  if (originalDialog(runtime)) return runtime.result(undefined);
  const stop=()=>({...runtime.result(undefined),data:{stage:runtime.window.ntsframework.session.get('jspName'),issued:false}});
  if (!await invoiceMove(runtime,w=>w.$('#etxivKndCd1').trigger('click'),'UTBETGAA05F001')) return stop();
  party(runtime,input.supplier,true);
  if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAA06F001',['공급자 정보가 저장되었습니다.'])) return stop();
  const number=String(input.buyer?.business_number ?? '').replaceAll('-','');
  ['bsno1','bsno2','bsno3'].forEach((id,i)=>runtime.setValue(id,[number.slice(0,3),number.slice(3,5),number.slice(5)][i]));
  const check=await runtime.invoke('ATEETGAA003R05',w=>w.$('#btnConfirm').trigger('click'));
  if (check?.branch !== 'success') return {...runtime.result(check),data:{issued:false,stage:'buyer_lookup'}};
  if (originalDialog(runtime).includes('정상적인 사업자등록번호 입니다')) {
    runtime.window.$('#popup_ok').trigger('click');
    await runtime.settle();
  }
  if (originalDialog(runtime)) return stop();
  party(runtime,input.buyer);
  if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAA09F001',['공급받는자 정보가 저장되었습니다.'])) return stop();
  runtime.setDate('txtWrtDt',input.date);
  if (input.date !== undefined) runtime.window.$('#txtWrtDt').trigger('change');
  if (originalDialog(runtime)) return stop();
  runtime.setValue('remark',input.remark);
  for (let i=0;i<(input.items || []).length;i++) {
    const w=runtime.window,item=input.items[i];
    if (i>=w.$('div[name="divN"]').length) w.btnAdd_onClick();
    if (originalDialog(runtime)) return stop();
    for (const [key,name] of Object.entries({month:'txtSplDt1',day:'txtSplDt2',name:'txtLsatNm',
      specification:'txtLsatRszeNm',quantity:'txtLsatQty',unit_price:'txtLsatUtprc',supply_amount:'txtLsatSplCft',
      tax_amount:'txtLsatTxamt',remark:'txtLsatRmrkCntn'})) {
      if (item[key] === undefined) continue;
      const field=w.$('input[name="'+name+'"]').eq(i);
      field.val(item[key]);
      // Source computes VAT/totals on blur; an explicit tax_amount is entered
      // afterwards just as on the original form and is never rounded by us.
      field.trigger('blur');
      if (originalDialog(runtime)) return stop();
    }
  }
  if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAA10F001',['품목 정보가 저장되었습니다.'])) return stop();
  for (const [key,id] of Object.entries({cash:'txtCsh',check:'txtChck',note:'txtNote',credit:'txtCrit'}))
    runtime.setValue(id,input.settlement?.[key]);
  if (input.settlement?.type !== undefined) {
    const w=runtime.window,type=input.settlement.type;
    // The source stores receipt/claim in the selected label's class.
    w.$('#rdRecApeClCdLabel'+(type == '02' || type === 'claim' ? '1' : '2')).trigger('click');
  }
  if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAA01F001',['결제 구분 정보가 저장되었습니다.'])) return stop();
  if (!await invoiceMove(runtime,w=>w.$('#btnIsn').trigger('click'),'UTBETGAA22F001')) return stop();
  if (originalDialog(runtime)) return stop();
  return {branch:'success',reason:'original_preview_ready',data:{issued:false,draft:invoiceDraft(runtime),account:runtime.account()}};
}
