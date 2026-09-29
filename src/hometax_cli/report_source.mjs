// Fetch the exact report viewer navigation for static analysis, without running
// its returned HTML/JS. Input and files contain session data: private paths only.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {BusinessRuntime} from './business.mjs';
import {getPage} from './browserless.mjs';

export async function writeReportSource(runtime, request, output, query, dependencies = {}) {
  await fs.mkdir(output,{mode:0o700});
  const response=await (dependencies.getSource || getPage)(request.url,runtime.page.jar,
    {...request,binary:true,signal:AbortSignal.timeout(Math.ceil(runtime.config.timeout*1000))});
  const body=Buffer.from(response.body);
  const source={file:'viewer-response.bin',url:response.url,status:response.status,
    content_type:response.content_type,bytes:body.length,sha256:createHash('sha256').update(body).digest('hex'),
    retrieved_at:new Date().toISOString()};
  await fs.writeFile(path.join(output,source.file),body,{mode:0o600,flag:'wx'});
  const record=runtime.record({branch:'no_action',reason:'source_saved_for_static_analysis',
    data:{query,request,source},report_branch:'unobserved',source_saved:true,returned_scripts_executed:false});
  record.scope='static_report_source_capture';
  const capture=path.join(output,'capture.json');
  await fs.writeFile(capture,JSON.stringify(record,null,2),{mode:0o600,flag:'wx'});
  return capture;
}

export async function captureReportSource(config, dependencies = {}) {
  if (!Number.isSafeInteger(Math.ceil(config.timeout * 1000)) || config.timeout <= 0)
    throw new Error('Invalid timeout');
  if (!['receipt','detail'].includes(config.kind)) throw new Error('Unknown report kind');
  if (config.query_source !== undefined && !['list','status'].includes(config.query_source))
    throw new Error('Unknown query source');
  // Reserve a new private directory before authentication or query requests.
  await fs.mkdir(config.output,{mode:0o700});
  const runtime = new BusinessRuntime({...config,command:'returns',operation:'report-source'},dependencies);
  let query, source, request, reason = 'session_unavailable';
  let captureError = false;
  let warnings = [];
  try {
    await runtime.open();
    if (runtime.ready) {
      query = await runtime.returns(config.query_source || 'list',{returnId:config.return_id});
      reason = 'return_query_not_success';
      if (query.branch === 'success') {
        const rows = config.query_source === 'status' ? query.data?.items : runtime.window.ttirnam101DVOListDes;
        if (!rows?.length) reason = 'no_return_selected';
        else if (config.return_id !== undefined && !rows.some(row=>row.rtnCvaId == config.return_id))
          reason = 'requested_return_not_found';
        else {
          const row = config.return_id === undefined ? rows[0] : rows.find(row=>row.rtnCvaId == config.return_id);
          request = config.query_source === 'status'
            ? await runtime.prepareReportFromStatus(row,config.kind,{disclose:config.disclose})
            : await runtime.prepareReportRequest(config.kind,{disclose:config.disclose});
          reason = 'report_navigation_unobserved';
          if (request) {
            reason = 'source_transfer_unobserved';
            const response = await (dependencies.getSource || getPage)(request.url,runtime.page.jar,
              {...request,binary:true,signal:AbortSignal.timeout(Math.ceil(config.timeout * 1000))});
            const body = Buffer.from(response.body);
            const filename = 'viewer-response.bin';
            await fs.writeFile(path.join(config.output,filename),body,{mode:0o600,flag:'wx'});
            source = {file:filename,url:response.url,status:response.status,
              content_type:response.content_type,bytes:body.length,
              sha256:createHash('sha256').update(body).digest('hex'),retrieved_at:new Date().toISOString()};
            reason = 'source_saved_for_static_analysis';
          }
        }
      }
    } else reason = runtime.unavailable().reason;
  } catch (error) {
    dependencies.onError?.(error);
    captureError = true;
    runtime.warnings.push('보고서 소스 확보 중 오류가 있습니다. 관찰한 조회 판정은 별도로 보존합니다.');
  } finally {
    try {
      const result = {branch:'no_action',reason,data:{query,request,source},
        report_branch:'unobserved',source_saved:Boolean(source),returned_scripts_executed:false};
      const record = runtime.page ? runtime.record(result) : {...result,warnings:runtime.warnings};
      record.scope = 'static_report_source_capture';
      warnings = record.warnings;
      await fs.writeFile(path.join(config.output,'capture.json'),JSON.stringify(record,null,2),{mode:0o600,flag:'wx'});
    } finally {runtime.close();}
  }
  return {scope:'static_report_source_capture',source_saved:Boolean(source),reason,
    query_branch:query?.branch,report_branch:'unobserved',returned_scripts_executed:false,
    http_status:source?.status,bytes:source?.bytes,capture_error:captureError,warnings};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;
    const result = await captureReportSource(JSON.parse(input));
    for (const warning of result.warnings) process.stderr.write('warning: '+warning+'\n');
    const {warnings,...summary} = result;
    process.stdout.write(JSON.stringify({...summary,warning_count:warnings.length})+'\n');
    // Zero means source-file capture only, never a report-service success.
    process.exitCode = result.source_saved ? 0 : result.capture_error ? 2 : 3;
  } catch (error) {
    process.stderr.write('error: 보고서 분석 입력 또는 파일 저장 오류 ('+error.constructor.name+')\n');
    process.exitCode = 2;
  }
}
