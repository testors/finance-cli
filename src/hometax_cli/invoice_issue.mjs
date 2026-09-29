// Explicit issuance of an already reviewed original-page draft. Never called by
// list/detail/prepare. No retries after C02/C03 or certificate callbacks.
import fs from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {invoiceMove, originalDialog, INVOICE_PAGES} from './invoice.mjs';
const clone=value=>value===undefined ? undefined : JSON.parse(JSON.stringify(value));
const NORMAL={xml:'ATEETGAA005C02',save:'ATEETGAA005C03',preview:'UTBETGAA22F001',mail:true};
function profile(prepared) {
  if (prepared.data?.kind!=='amendment') return NORMAL;
  const dual=['01','05'].includes(prepared.data.draft.etxivObj?.etxivMdfRsnCd);
  return {xml:'ATEETGAC001C02',save:'ATEETGAC001C03',preview:dual?'UTBETGAC20F001':'UTBETGAC19F001',dual,mail:false};
}

export function issuanceResult(runtime) {
  const p=runtime.invoiceProfile || NORMAL;
  const xml=runtime.last(p.xml), auth=runtime.last('ATXPPABA002A07'),
    saved=runtime.last(p.save), mail=p.mail ? runtime.last('ATEETBAA002C08') : undefined;
  let branch='no_action',reason='issuance_completion_unobserved';
  if (mail?.response_observed) {branch=mail.branch;reason='original_email_result';}
  else if (saved?.response_observed && (!p.mail || saved.branch==='failure')) {branch=saved.branch;reason='original_storage_result';}
  else if (auth?.response_observed && runtime.window?.PubcUserPkcDcryInfrSVO?.certScsYn != 'Y') {
    branch='failure';reason='original_certificate_rejected';
  } else if (xml?.branch==='failure') {branch='failure';reason='original_xml_result';}
  else if (runtime.invoiceSignatureRejected) {branch='failure';reason='original_xml_signature_missing';}
  else if (xml?.branch==='success' && (runtime.window?.xmlCntn == null || runtime.window.xmlCntn == '')) {
    branch='failure';reason='original_xml_empty';
  }
  return {...runtime.result(mail || saved || auth || xml),branch,reason,data:{
    storage_branch:saved?.branch || 'no_action',notification_branch:mail?.branch || 'no_action',
    approval_number:clone(saved?.response?.apprvNo),
    ...(!p.mail ? {kind:'amendment',original_approval_number:runtime.window?.ntsframework.session.get('etan'),
      ...(p.dual ? {cancellation_approval_number:clone(saved?.response?.apprvNo),
        replacement_approval_number:clone(saved?.response?.oldAprvNo)} : {})} : {}),
    source:clone(saved?.response),notification_source:clone(mail?.response),
    // Once a request has started, transport/host uncertainty is not permission
    // to repeat the operation. The approval number can be checked by detail.
    automatic_retry:false}};
}

async function sign(config,xml,oid,xml2) {
  const child=spawn(process.env.FINANCE_PYTHON || 'python',['-m','hometax_cli.invoice_certificate'],{stdio:['pipe','pipe','pipe']});
  let stdout='';
  child.stdout.on('data',chunk=>stdout+=chunk);
  child.stderr.resume();
  const complete=new Promise((resolve,reject)=>{
    child.once('error',reject);child.once('close',code=>code===0 ? resolve() : reject(new Error('Certificate processing incomplete')));
  });
  child.stdin.on('error',()=>{});
  child.stdin.end(JSON.stringify({credential:config.credential,password:config.password,xml,xml2,oid}));
  await complete;
  return JSON.parse(stdout);
}

export async function invoiceIssue(runtime) {
  const c=runtime.config,prepared=JSON.parse(await fs.readFile(c.prepared,'utf8'));
  if (prepared.reason!=='original_preview_ready' || !prepared.data?.draft)
    return {branch:'no_action',reason:'original_preview_required'};
  const p=runtime.invoiceProfile=profile(prepared);
  try {
    await fs.access(c.prepared+'.issue-attempt');
    return {branch:'no_action',reason:'previous_issuance_attempt',data:{automatic_retry:false}};
  } catch (error) {if(error.code!=='ENOENT') throw error;}
  if (!await runtime.menu(INVOICE_PAGES.list)) return runtime.unavailable();
  if (originalDialog(runtime)) return runtime.result(undefined);
  if (runtime.account().tin != prepared.data.account?.tin)
    return {branch:'no_action',reason:'prepared_business_context_changed'};
  for (const [key,value] of Object.entries(prepared.data.draft)) runtime.window.ntsframework.session.set(key,value);
  if (!await invoiceMove(runtime,w=>w.nts_openPage(p.preview),p.preview)) return runtime.result(undefined);
  if (originalDialog(runtime)) return runtime.result(undefined);
  let checked;
  try {checked=await sign(c,undefined,runtime.window.etCm_OidList());}
  catch (_) {
    runtime.warnings.push('인증서·비밀번호·로컬 XML 서명을 확인하지 못했습니다. 발급 요청 전 중단했습니다.');
    return {branch:'no_action',reason:'local_certificate_preflight_incomplete',data:{issued:false}};
  }
  runtime.warnings.push(...checked.warnings);
  if (!checked.selection.selectable)
    return {branch:'no_action',reason:'original_certificate_not_selectable',data:{certificate:checked.selection,issued:false}};
  // One prepared transaction gets one attempt, including uncertain outcomes.
  // This is local duplicate prevention, separate from the original verdict.
  let attempt;
  try {attempt=await fs.open(c.prepared+'.issue-attempt','wx',0o600);}
  catch (e) {if(e.code==='EEXIST') return {branch:'no_action',reason:'previous_issuance_attempt',data:{automatic_retry:false}};throw e;}
  await attempt.writeFile(JSON.stringify({output:c.output,started_at:new Date().toISOString()}));
  await attempt.close();
  let nativeRequest;
  const w=runtime.window,original=w.nts_callNative;
  w.nts_callNative=function(action,data){
    if(action==='XMLSIGNITURE') nativeRequest=clone(data);
    return original.apply(this,arguments);
  };
  await runtime.invoke('ATEETGAA005R14',w=>w.$('#btnIsn_popup').trigger('click'));
  // These are the original final transaction confirmation and optional delay
  // notices. The explicit issue command authorizes this prepared transaction.
  // Unrecognized dialogs stay pending; no blanket confirmation handler exists.
  for(let i=0;i<4;i++) {
    const message=originalDialog(runtime);
    if (!message) break;
    if (!message.includes('발급하시겠습니까?') && !message.includes('지연발급 가산세 대상이 될수 있습니다.')) break;
    w.$('#popup_ok').trigger('click');
    await runtime.settle();
  }
  await runtime.until(()=>w.document.getElementById('certifiLgnBox') || originalDialog(runtime));
  if (originalDialog(runtime) || !w.document.getElementById('certifiLgnBox')) return issuanceResult(runtime);
  // Original certificate-method selector dispatches C02, never a fabricated API.
  await runtime.invoke(p.xml,w=>w.$('#certifiLgnBox').trigger('click'));
  if (!nativeRequest) return issuanceResult(runtime);
  const signed=await sign(c,String(w.xmlCntn),nativeRequest.oid,p.dual ? String(w.xmlCntn2) : undefined);
  runtime.warnings.push(...signed.warnings);
  if (!signed.selection.selectable)
    return {...issuanceResult(runtime),reason:'original_certificate_not_selectable',data:{certificate:signed.selection,issued:false}};
  const payload=signed.callback;
  runtime.invoiceSignatureRejected=!payload?.xmlSigniture || (p.dual && !payload?.xmlSigniture2);
  await runtime.invoke(p.save,w=>w.nts_calledByNative(signed.callback));
  await runtime.settle();
  return issuanceResult(runtime);
}
