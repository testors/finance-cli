import test from 'node:test';
import assert from 'node:assert/strict';
import {issuanceResult} from '../../src/hometax_cli/invoice_issue.mjs';
import {invoiceMove} from '../../src/hometax_cli/invoice.mjs';

function runtime(services,dual=false) {
  return {invoiceProfile:{xml:'XML',save:'SAVE',mail:false,dual},
    last:action=>services[action],result:service=>({branch:service?.branch || 'no_action'}),
    window:{ntsframework:{session:{get:()=> 'ORIGINAL'}},PubcUserPkcDcryInfrSVO:{certScsYn:'Y'},xmlCntn:'XML'}};
}
test('amendment storage succeeds without normal-issuance email or approval fields',()=>{
  const r=issuanceResult(runtime({SAVE:{branch:'success',response_observed:true,response:{RESULT:{result:['S']}}}}));
  assert.equal(r.branch,'success');assert.equal(r.data.notification_branch,'no_action');
  assert.equal(r.data.approval_number,undefined);assert.equal(r.data.automatic_retry,false);
});
test('paired amendment maps oldAprvNo to replacement, keeps original distinct',()=>{
  const r=issuanceResult(runtime({SAVE:{branch:'success',response_observed:true,response:{apprvNo:'CANCEL',oldAprvNo:'REPLACE'}}},true));
  assert.equal(r.data.cancellation_approval_number,'CANCEL');
  assert.equal(r.data.replacement_approval_number,'REPLACE');
  assert.equal(r.data.original_approval_number,'ORIGINAL');
});
test('amendment mapped certificate verdict and missing second signature remain failures',()=>{
  const r=runtime({XML:{branch:'success',response_observed:true},AUTH:{}});
  r.invoiceSignatureRejected=true;assert.equal(issuanceResult(r).branch,'failure');
  r.invoiceSignatureRejected=false;
  r.last=id=>id==='ATXPPABA002A07'?{branch:'success',response_observed:true}:undefined;
  r.window.PubcUserPkcDcryInfrSVO.certScsYn='N';
  assert.equal(issuanceResult(r).reason,'original_certificate_rejected');
});
test('navigation observed after asynchronous source error is retained; absent navigation is not fabricated',async()=>{
  const r={window:{},warnings:[],ready:true,settle:async()=>{r.navigation={url:'https://example.test/?actionId=TARGET'};},
    navigate:async request=>assert.equal(new URL(request.url).searchParams.get('actionId'),'TARGET')};
  assert.equal(await invoiceMove(r,()=>{throw new ReferenceError('pageId');},'TARGET'),true);
  assert.equal(r.warnings.length,1);
  r.settle=async()=>{};
  await assert.rejects(invoiceMove(r,()=>{throw new ReferenceError('pageId');},'TARGET'),ReferenceError);
});
