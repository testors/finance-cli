import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {once} from 'node:events';
import {gzipSync} from 'node:zlib';
import {getPage, loadDOM} from '../../src/hometax_cli/browserless.mjs';

test('HTTP bootstrap retains redirect and HttpOnly cookies without a browser', async () => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({url:request.url, cookie:request.headers.cookie, ua:request.headers['user-agent']});
    if (request.url === '/start') {
      response.writeHead(302, {'Set-Cookie':'session=synthetic; HttpOnly; Path=/', Location:'/page'});
      response.end();
    } else {
      response.writeHead(200, {'Set-Cookie':'JspName=synthetic; Path=/'});
      response.end('<html>synthetic</html>');
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const {CookieJar} = loadDOM();
    const jar = new CookieJar();
    const base = `http://127.0.0.1:${server.address().port}`;
    const result = await getPage(base + '/start', jar);
    assert.equal(result.status, 200);
    assert.equal(result.url, base + '/page');
    assert.equal(requests[1].cookie, 'session=synthetic');
    assert.ok(requests.every(r=>r.ua.endsWith(' Android511')));
    assert.equal(jar.getCookiesSync(base).find(c=>c.key==='session').httpOnly, true);
    assert.equal(jar.getCookiesSync(base).find(c=>c.key==='JspName').value, 'synthetic');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('static source capture retains binary response bytes and status without interpreting HTML', async () => {
  const bytes = Buffer.from([0,0xff,0x80,0x3c,0x73,0x63,0x72,0x69,0x70,0x74,0x3e]);
  const server = http.createServer((request,response)=>{
    response.writeHead(500,{'Content-Type':'application/octet-stream','Content-Encoding':'gzip'});
    response.end(gzipSync(bytes));
  });
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  try {
    const {CookieJar} = loadDOM();
    const response = await getPage(`http://127.0.0.1:${server.address().port}/source`,new CookieJar(),{binary:true});
    assert.deepEqual(response.body,bytes);
    assert.equal(response.status,500);
    assert.equal(response.content_type,'application/octet-stream');
  } finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

test('navigation referrers follow origin boundaries and redirect policy without leaking paths or fragments', async () => {
  const requests = [];
  const server = http.createServer((request,response)=>{
    requests.push({url:request.url,referrer:request.headers.referer,origin:request.headers.origin});
    if (request.url === '/redirect') {
      response.writeHead(302,{Location:'/final','Referrer-Policy':'no-referrer'});
      response.end();
    } else response.end('synthetic');
  });
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  try {
    const {CookieJar} = loadDOM();
    const jar = new CookieJar(), base = `http://127.0.0.1:${server.address().port}`;
    await getPage(base+'/same',jar,{referrer:base+'/source?query=retained#fragment'});
    assert.equal(requests.at(-1).referrer,base+'/source?query=retained');
    await getPage(base+'/report',jar,{method:'POST',body:'param=synthetic',
      referrer:'https://mob.tbht.hometax.go.kr/jsonAction.do?actionId=UTBPPZAA07F001#fragment'});
    assert.equal(requests.at(-1).referrer,'https://mob.tbht.hometax.go.kr/');
    assert.equal(requests.at(-1).origin,'https://mob.tbht.hometax.go.kr');
    await getPage(base+'/redirect',jar,{referrer:base+'/source'});
    assert.equal(requests.at(-2).referrer,base+'/source');
    assert.equal(requests.at(-1).url,'/final');
    assert.equal(requests.at(-1).referrer,undefined);
  } finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
