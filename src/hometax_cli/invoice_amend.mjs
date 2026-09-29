// Drive unmodified amendment pages. This command stops at the preview.
import {invoiceMove,invoiceDraft,originalDialog,party} from './invoice.mjs';

export const AMEND_REASONS={correction:'01','amount-change':'02',return:'03',
  cancellation:'04','local-credit':'05',duplicate:'06'};
const entry={server:'ET',screen:'UTBETGAD01F001',menu:'8006010300',cert:'03',
  userCert:'null',title:'전자(세금)계산서수정발급'};
const extra=['etxivObj2','splrInfrBIzSVO2','dmnrInfrBizSVO2','trteInfrBizSVO2',
  'lsatInfrBizSVOList2','sncClInfrBizSVO2','sncInfrBizSVO2','etan','etxivKndCd',
  'etxivClsfCd','etxivMdfRsnCd','tfstWrtClCd','tfstSumAmt','isnDtm','frstWrtFg',
  'frsMdfYn','lsatInfrStorYn','dmnrChngYn','splCftChng'];

// Preserve the original field restrictions. Supplying a locked value must not
// let a headless caller edit something unavailable in the original form.
function field(runtime,element,value,event) {
  if (value===undefined) return;
  if (!element.length || element.prop('disabled') || element.prop('readOnly') || element.hasClass('disabled')) {
    if (!element.length || String(element.val())!==String(value))
      runtime.warnings.push('서비스 수정 화면에서 입력할 수 없는 필드가 있어 기존 값을 유지했습니다.');
    return;
  }
  element.val(value);
  if (event) element.trigger(event);
}
function editParty(runtime,values,supplier=false) {
  const original=runtime.setValue;
  runtime.setValue=(id,value)=>field(runtime,runtime.window.$('#'+id),value);
  try {party(runtime,values,supplier);} finally {runtime.setValue=original;}
}

export async function invoiceAmend(runtime,input={}) {
  const reason=AMEND_REASONS[runtime.config.reason] || runtime.config.reason;
  const dual=['01','05'].includes(reason), main=dual?'UTBETGAC21F001':'UTBETGAC05F001';
  const preview=dual?'UTBETGAC20F001':'UTBETGAC19F001';
  const stop=(service)=>({...runtime.result(service),data:{issued:false,
    stage:runtime.window.ntsframework.session.get('jspName'),amendment_reason:reason}});
  if (!await runtime.menu(entry)) return runtime.unavailable();
  if (originalDialog(runtime).includes('로그인한 인증서는 전자(세금)계산서 발급용 인증서가 아닙니다.'))
    runtime.window.$('#popup_ok').trigger('click');
  if (originalDialog(runtime)) return stop();
  if (!await invoiceMove(runtime,w=>w.$('#btn_gac01').trigger('click'),'UTBETGAC02F001')) return stop();
  runtime.setValue('num1',runtime.config.approval_number);
  const queried=await runtime.invoke('ATEETGBA001R05',w=>w.btnSearch_onClick());
  if (queried?.branch!=='success') return stop(queried);
  await runtime.until(()=>runtime.window.document.getElementById('btnIsn') || originalDialog(runtime));
  if (!runtime.window.document.getElementById('btnIsn') || originalDialog(runtime)) return stop(queried);
  if (!await invoiceMove(runtime,w=>w.$('#btnIsn').trigger('click'),'UTBETGAC04F001')) return stop();
  const idx=['01','06','02','04','03','05'].indexOf(reason);
  if (idx<0 || runtime.window.$('.with_btn a').eq(idx).closest('li').css('display')==='none')
    return {...stop(),reason:'original_amendment_reason_unavailable'};
  if (!await invoiceMove(runtime,w=>w.$('.with_btn a').eq(idx).trigger('click'),main))
    return {...stop(),reason:'original_amendment_route_unavailable'};
  const source=runtime.last('ATEETGAC002R01');
  if (source?.branch!=='success') return stop(source);
  let screen=main;
  if (originalDialog(runtime).includes('품목 정보등록 화면으로 이동합니다.')) {
    if (!await invoiceMove(runtime,w=>w.$('#popup_ok').trigger('click'),'UTBETGAC16F001')) return stop();
    screen='UTBETGAC16F001';
  }
  if (originalDialog(runtime)) return stop();
  if (screen==='UTBETGAC16F001' && (input.supplier || input.buyer)) {
    screen=input.supplier?'UTBETGAC11F001':'UTBETGAC12F001';
    if (!await invoiceMove(runtime,w=>w.$('#quadStep li').eq(input.supplier?0:1).trigger('click'),screen)) return stop();
  }
  // Amount-change/return automatically start at the item form. Other reasons
  // enter the requested form through the source's table click handler.
  if (screen===main) {
    const step=input.supplier ? 'supplier' : input.buyer ? 'buyer'
      : input.items!==undefined || input.date!==undefined || input.remark!==undefined || reason==='01' ? 'items'
      : input.settlement ? 'settlement' : undefined;
    if (step) {
      const indices={supplier:1,buyer:2,items:3,settlement:5};
      screen={supplier:'UTBETGAC11F001',buyer:'UTBETGAC12F001',items:'UTBETGAC16F001',settlement:'UTBETGAC18F001'}[step];
      if (!await invoiceMove(runtime,w=>w.$('table').eq(indices[step]+(dual?5:0)).trigger('click'),screen)) return stop();
    }
  }
  if (screen==='UTBETGAC11F001') {
    editParty(runtime,input.supplier,true);
    if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAC12F001',['공급자 정보가 저장되었습니다.'])) return stop();
    screen='UTBETGAC12F001';
  }
  if (screen==='UTBETGAC12F001') {
    const w=runtime.window;
    if (input.buyer?.business_number!==undefined) {
      const n=String(input.buyer.business_number).replaceAll('-','');
      ['bsno1','bsno2','bsno3'].forEach((id,i)=>field(runtime,w.$('#'+id),[n.slice(0,3),n.slice(3,5),n.slice(5)][i],'change'));
    }
    if (!w.$('#btnConfirm').prop('disabled')) {
      const checked=await runtime.invoke('ATEETGAA003R05',w=>w.$('#btnConfirm').trigger('click'));
      if (checked?.branch!=='success') return stop(checked);
      if (originalDialog(runtime).includes('정상적인 사업자등록번호 입니다')) {
        w.$('#popup_ok').trigger('click');await runtime.settle();
      }
      if (originalDialog(runtime)) return stop();
    }
    editParty(runtime,input.buyer);
    if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAC16F001',['공급받는자 정보가 저장되었습니다.'])) return stop();
    screen='UTBETGAC16F001';
  }
  if (screen==='UTBETGAC16F001') {
    const w=runtime.window;
    if (input.date!==undefined) {
      if (w.$('#txtWrtDt').hasClass('able')) {runtime.setDate('txtWrtDt',input.date);w.$('#txtWrtDt').trigger('change');}
      else runtime.warnings.push('서비스 수정 화면에서 작성일이 고정되어 기존 값을 유지했습니다.');
    }
    if (originalDialog(runtime)) return stop();
    field(runtime,w.$('#remark'),input.remark);
    if (input.items) {
      while (w.$('div[name=divN]').length>Math.max(1,input.items.length)) {
        const button=w.$('button[name=btnDel]').last();
        if (button.prop('disabled')) break;
        const before=w.$('div[name=divN]').length;button.trigger('click');
        if (originalDialog(runtime) || w.$('div[name=divN]').length===before) break;
      }
      if (input.items.length===0) {
        w.$('button[name=btnDel]').first().trigger('click');
        if (originalDialog(runtime)) return stop();
      }
      for (let i=0;i<input.items.length;i++) {
        if (i>=w.$('div[name=divN]').length) w.$('#btnAdd').trigger('click');
        if (originalDialog(runtime)) return stop();
        for (const [key,name] of Object.entries({month:'txtSplDt1',day:'txtSplDt2',name:'txtLsatNm',
          specification:'txtLsatRszeNm',quantity:'txtLsatQty',unit_price:'txtLsatUtprc',supply_amount:'txtLsatSplCft',
          tax_amount:'txtLsatTxamt',remark:'txtLsatRmrkCntn'})) {
          field(runtime,w.$('input[name='+name+']').eq(i),input.items[i][key],'blur');
          if (originalDialog(runtime)) return stop();
        }
      }
    }
    if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),'UTBETGAC18F001',['품목 정보가 저장되었습니다.'])) return stop();
    screen='UTBETGAC18F001';
  }
  if (screen==='UTBETGAC18F001') {
    for (const [key,id] of Object.entries({cash:'txtCsh',check:'txtChck',note:'txtNote',credit:'txtCrit'}))
      field(runtime,runtime.window.$('#'+id),input.settlement?.[key]);
    if (input.settlement?.type!==undefined) {
      const type=input.settlement.type;
      const label=runtime.window.$('#rdRecApeClCdLabel'+(type=='02'||type==='claim'?'1':'2'));
      if (label.hasClass('disabled')) runtime.warnings.push('서비스에서 결제 구분 변경이 비활성화되어 기존 값을 유지했습니다.');
      else label.trigger('click');
    }
    if (!await invoiceMove(runtime,w=>w.$('#btnSave').trigger('click'),main,['결제 구분 정보가 저장되었습니다.'])) return stop();
  }
  if (!await invoiceMove(runtime,w=>w.$('.btn_wrap button').eq(3).trigger('click'),preview,
    ['당초 발급금액의 전액을 계약해제로 수정발급 하시겠습니까?'])) return stop();
  if (originalDialog(runtime)) return stop();
  return {branch:'success',reason:'original_preview_ready',data:{kind:'amendment',issued:false,
    original_approval_number:runtime.window.ntsframework.session.get('etan'),amendment_reason:reason,
    document_count:dual?2:1,draft:invoiceDraft(runtime,extra),account:runtime.account()}};
}
