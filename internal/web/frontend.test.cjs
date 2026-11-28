const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function harness() {
  function element() {
    return {textContent:'',innerHTML:'',value:'',style:{},dataset:{},classList:{add(){},remove(){}},addEventListener(){},appendChild(){},remove(){},focus(){},select(){},querySelector(){return null;},querySelectorAll(){return [];}};
  }
  const elements = new Map();
  const document = {hidden:false,addEventListener(){},getElementById(id){if (!elements.has(id)) elements.set(id,element());return elements.get(id);},createElement:element,querySelectorAll(){return [];},body:element()};
  const sockets = [];
  const calls = [];
  const timers = new Map();
  const events = {};
  let timerID = 0;
  const context = vm.createContext({document,console,navigator:{},location:{protocol:'https:',host:'192.0.2.1:52520',hostname:'192.0.2.1',hash:'',pathname:'/'},history:{replaceState(){calls.push('remove-fragment');}},window:{addEventListener(name,fn){events[name]=fn;}},setInterval(){},setTimeout(fn,delay){const id=++timerID;timers.set(id,{fn,delay});return id;},clearTimeout(id){timers.delete(id);},AbortController,URLSearchParams,alert(){},fetch:async (url)=>{calls.push(url);return {ok:true,json:async()=>({self:{peer_id:'self'},peers:[],discoverable:{},stats:{max_messages:2}})};},WebSocket:class {constructor(){this.readyState=0;sockets.push(this);}close(code){this.readyState=3;if(this.onclose)this.onclose({code});}}});
  let source = fs.readFileSync(path.join(__dirname,'static/app.js'),'utf8');
  source = source.replace(/  bootstrap\(\)\.catch\([^\n]+\);/, `globalThis.api = {buildMessageCard, deliveryHtml, connectWS, bootstrap, removePeer, getMessages:()=>messages, setState:(s)=>{appState=s;}};`);
  vm.runInContext(source,context);
  return {api:context.api,context,sockets,calls,timers,events};
}

test('remote fields cannot inject markup or navigation URLs',()=>{
  const {api}=harness();api.setState({self:{peer_id:'self'}});
  const card=api.buildMessageCard({id:'safe',kind:'image',sender_os:'<img src=x onerror=alert(1)>',sender_name:'<b>name</b>',inline_url:'" onerror="alert(1)',created_at:0});
  assert.ok(!card.innerHTML.includes('onerror'));
  assert.ok(card.innerHTML.includes('&lt;b&gt;name&lt;/b&gt;'));
  assert.ok(card.innerHTML.includes('src="/api/inline/safe"'));
  const file=api.buildMessageCard({kind:'file',sender_os:'linux',created_at:0,file:{file_id:'safe',file_name:'archive',download_url:'javascript:alert(1)',owner_peer_id:'other'}});
  assert.ok(!file.innerHTML.includes('javascript:'));
  assert.ok(file.innerHTML.includes('/api/files/proxy/safe'));
});

test('browser retention follows server eviction and message count',()=>{
  const {api,sockets}=harness();api.setState({self:{peer_id:'self'},peers:[],stats:{max_messages:2}});api.connectWS();const ws=sockets[0];
  const send=(type,data)=>ws.onmessage({data:JSON.stringify({type,data})});
  for(let i=0;i<3;i++)send('new_message',{id:String(i),kind:'text',text:'test',created_at:0});
  assert.equal(api.getMessages().length,2);
  send('stats_update',{stats:{max_messages:2},message_ids:['2']});
  assert.equal(api.getMessages().length,1);assert.equal(api.getMessages()[0].id,'2');
  send('message_delivery',{id:'2',delivery:{peer:'failed'}});
  assert.equal(api.getMessages()[0].delivery.peer,'failed');
});

test('QR token is removed from browser URL before exchanging for a cookie',async()=>{
  const {api,context,calls}=harness();context.location.hash='#token=secret';await api.bootstrap();
  assert.equal(calls[0],'remove-fragment');assert.equal(calls[1],'/api/session');
  assert.ok(!calls.includes('/api/pairing-info'));
});

test('reconnect uses exponential backoff and stops after eight attempts',async()=>{
 const h=harness();h.api.connectWS();
 for(let attempt=0;attempt<8;attempt++){
  await h.sockets.at(-1).onclose({code:1006});
  assert.equal(h.timers.size,1);
  const [id,timer]=[...h.timers][0];
  assert.equal(timer.delay,Math.min(30000,1000*2**attempt));
  h.timers.delete(id);timer.fn();
 }
 await h.sockets.at(-1).onclose({code:1006});
 assert.equal(h.sockets.length,9);assert.equal(h.timers.size,0);
});
test('server shutdown and pagehide do not schedule reconnect traffic',async()=>{
 const h=harness();h.api.connectWS();await h.sockets[0].onclose({code:1001});
 assert.equal(h.timers.size,0);assert.equal(h.calls.length,0);
 const page=harness();page.api.connectWS();page.events.pagehide();
 await Promise.resolve();assert.equal(page.timers.size,0);assert.equal(page.calls.length,0);
});
test('successful init resets backoff and duplicate connects are ignored',async()=>{
 const h=harness();h.api.connectWS();h.api.connectWS();assert.equal(h.sockets.length,1);
 await h.sockets[0].onclose({code:1006});let [id,timer]=[...h.timers][0];h.timers.delete(id);timer.fn();
 h.sockets[1].onmessage({data:JSON.stringify({type:'init',data:{state:{self:{peer_id:'self'},peers:[],discoverable:{},stats:{max_messages:2}},messages:[]}})});
 await h.sockets[1].onclose({code:1006});assert.equal([...h.timers.values()][0].delay,1000);
});

test('peer list updates preserve the local pairing code', async () => {
  const {api, context} = harness();
  context.location.hostname = '127.0.0.1';
  context.confirm = () => true;
  const state = {self: {peer_id: 'self'}, peers: [], discoverable: {}, stats: {}};
  context.fetch = async url => ({
    ok: true,
    json: async () => url === '/api/pairing-info' ? {pin: '123456'} : state,
  });
  await api.bootstrap();
  const pin = context.document.getElementById('selfPIN');
  assert.equal(pin.textContent, '123456');
  await api.removePeer('other');
  assert.equal(pin.textContent, '123456');
});
