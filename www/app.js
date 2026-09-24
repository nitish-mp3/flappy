'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stamp = value => value ? new Date(value*1000).toLocaleString() : '—';
let config, runtime = {}, dirty = false, editing = null, discoveries = [], busy = false;
async function api(path, body) {
  const response = await fetch('api/' + path, body === undefined ? {cache:'no-store'} : {
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || 'Request failed');
  return data;
}
function toast(message) { $('toast').textContent=message; $('toast').hidden=false; clearTimeout(toast.timer); toast.timer=setTimeout(()=>$('toast').hidden=true,7000); }
function changed() { dirty=true; $('savebar').hidden=false; $('save-state').textContent='Unsaved changes'; }
function navigate(page) {
  document.querySelectorAll('[data-page]').forEach(b=>b.setAttribute('aria-selected',b.dataset.page===page));
  document.querySelectorAll('main>section').forEach(s=>s.hidden=s.id!==page);
}
function renderInterfaces() {
  for (const role of ['fallback','monitor']) {
    const list=config.interfaces.filter(i=>i.role===role);
    $(role+'-list').innerHTML=list.length ? list.map((i,n)=>`<div class="row">
      <div class="rank">${role==='fallback'?n+1:'◎'}</div><div class="row-main"><h3>${esc(i.name)}</h3>
      <small>${i.type==='usb'?'USB · '+esc(i.device):esc(i.host)+':'+i.port+' · '+esc(i.protocol).toUpperCase()}${i.secure?' · Secure':''}${i.telegrams?' · Telegram monitor':''}</small></div>
      <div class="actions">${role==='fallback'?`<button class="small" data-move="-1" data-id="${esc(i.id)}" ${n===0?'disabled':''} aria-label="Move ${esc(i.name)} up">↑</button><button class="small" data-move="1" data-id="${esc(i.id)}" ${n===list.length-1?'disabled':''} aria-label="Move ${esc(i.name)} down">↓</button>`:''}
      <button class="small" data-edit="${esc(i.id)}">Edit</button><button class="small danger" data-remove="${esc(i.id)}">Remove</button></div></div>`).join(''):
      `<div class="empty">${role==='fallback'?'Add an IP or USB interface to get started.':'Add interfaces here to watch their availability without using them for failover.'}</div>`;
  }
}
function fillSettings() {
  document.querySelectorAll('[data-setting]').forEach(el=>{
    if(el.type==='checkbox') el.checked=!!config[el.dataset.setting]; else el.value=config[el.dataset.setting];
  });
}
async function refresh() {
  if(busy) return; busy=true;
  try {
    const [status, interfaces, events] = await Promise.all([api('status'),api('interfaces'),api('events')]);
    runtime=interfaces;
    $('connection').textContent='Connected'; $('connection').className='pill up';
    $('pending').hidden=!interfaces.needs_restart;
    $('stale').hidden=!interfaces.stale||interfaces.legacy_mode; $('migration').hidden=!interfaces.legacy_mode;
    const active=(interfaces.interfaces||[]).find(i=>i.active);
    $('active-name').textContent=active?.name || (status.backend?status.backend.host:'No active interface');
    $('active-detail').textContent=active ? 'Selected for Home Assistant connections' : (status.backend?'Legacy manager · save and restart to enable the new interface manager':'Waiting for a healthy fallback interface');
    $('sessions-count').textContent=status.active_sessions+' / '+status.max_sessions;
    $('switch-count').textContent=status.total_failovers;
    $('uptime').textContent=Math.floor(status.uptime_s/3600)+'h '+Math.floor(status.uptime_s%3600/60)+'m';
    $('live-list').innerHTML=(interfaces.interfaces||[]).map(i=>`<div class="card"><div class="head"><div><h3>${esc(i.name)}</h3><small>${i.role==='monitor'?'Monitor only':'Fallback interface'}${i.active?' · Active':''}</small></div><span class="pill ${interfaces.stale?'':i.healthy?'up':i.healthy===false?'down':''}">${interfaces.stale?'Stale':esc(i.status)}</span></div>
      <div class="grid"><small>Response<br><strong>${i.latency_ms==null?'—':Math.round(i.latency_ms)+' ms'}</strong></small><small>Checks / failed<br><strong>${i.checks} / ${i.failures}</strong></small><small>Last down<br><strong>${stamp(i.last_down)}</strong></small><small>Last up<br><strong>${stamp(i.last_up)}</strong></small></div>
      ${i.error?'<p class="muted">'+esc(i.error)+'</p>':''}
      ${i.telegrams?`<details><summary>Telegrams · ${i.telegrams.received} received · ${esc(i.telegrams.state)}</summary><p>${esc(i.telegrams.error)}</p><small>Duplicates: ${i.telegrams.duplicates} · Last received: ${stamp(i.telegrams.last_telegram)}</small>${i.telegrams.recent.map(t=>`<p><small>${stamp(t.timestamp)}</small><br><code>${esc(t.cemi)}</code></p>`).join('')}</details>`:''}
      ${i.role==='fallback'&&i.healthy&&!i.active&&!interfaces.stale?`<button class="small" data-select="${esc(i.id)}">Use this interface now</button>`:''}</div>`).join('')||'<div class="empty">Live status appears after saving your interfaces and restarting.</div>';
    $('events-body').innerHTML=events.events.map(e=>`<tr><td>${stamp(e.timestamp)}</td><td>${esc(config.interfaces.find(i=>i.id===e.interface_id)?.name||e.interface_id||'System')}</td><td>${esc(e.kind)}</td><td>${esc(e.message)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">No events recorded yet.</td></tr>';
    $('sessions-body').innerHTML=(status.sessions||[]).map(s=>`<tr><td>${esc(s.channel_id)}</td><td>${esc(s.client_addr)}</td><td>${esc(s.backend_addr)}</td><td>${s.telegrams}</td><td>${s.bytes_in} / ${s.bytes_out}</td><td>${s.errors}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">No active Home Assistant sessions.</td></tr>';
  } catch(e) { $('connection').textContent='Reconnecting'; $('connection').className='pill down'; $('stale').hidden=false; }
  finally {busy=false;}
}
function openEditor(item={}, role='fallback') {
  editing=item.id||null; openEditor.device=item.device; openEditor.identity={serial:item.serial||'',vendor_id:item.vendor_id||'',product_id:item.product_id||''}; $('probe-result').textContent=''; $('editor-form').reset(); $('editor-error').textContent='';
  const defaults={name:'',type:'ip',role,host:'',port:3671,protocol:'auto',device:'',mode:'auto',baud:19200,secure:false,user_id:1,telegrams:false,extra_args:'',knx_address:'',client_address:''};
  Object.entries({...defaults,...item}).forEach(([key,value])=>{const el=$('i-'+key);if(el) {if(el.type==='checkbox')el.checked=!!value;else el.value=value;}});
  for(const key of ['device_password','user_password']) {$('i-'+key).value=item[key]||'';$('i-'+key).placeholder=item[key+'_set']?'Saved · leave blank to keep':'Enter password';}
  $('editor-title').textContent=editing?'Edit interface':'Add interface'; editorType(); $('editor').showModal();
}
function editorType() {
  const usb=$('i-type').value==='usb'; $('ip-fields').hidden=usb; $('usb-fields').hidden=!usb;
  $('i-host').required=!usb; $('i-device').required=usb; $('secure-fields').hidden=!$('i-secure').checked;
}
async function scan(type) {
  const button=$(type==='usb'?'scan-usb':'scan-ip'); button.disabled=true; button.textContent='Scanning…';
  try {
    const result=type==='usb'?await api('usb'):await api('discover',{local_ip:$('scan-local').value.trim()||'0.0.0.0'});
    discoveries=(result.devices||[]).map(d=>type==='usb'?{name:[d.vendor,d.product].filter(Boolean).join(' ')||'USB interface',type:'usb',device:d.path,mode:'auto',serial:d.serial||'',vendor_id:d.vendor_id||'',product_id:d.product_id||''}:{name:d.name||d.host,type:'ip',host:d.host,port:d.port,protocol:'auto',tunnelling:d.tunnelling});
    $('discovery-results').innerHTML=discoveries.map((d,n)=>`<div class="row"><div class="row-main"><h3>${esc(d.name)}</h3><small>${esc(d.device||d.host+':'+d.port)}${d.tunnelling===false?' · No tunnelling service advertised':''}</small></div><div class="actions"><button class="small" data-discovered="${n}" data-role="fallback">Add to fallback</button><button class="small" data-discovered="${n}" data-role="monitor">Monitor only</button></div></div>`).join('')||'<div class="empty">No interfaces found. You can still add one by address or device path.</div>';
  }catch(e){toast(e.message);}finally{button.disabled=false;button.textContent=type==='usb'?'Scan USB':'Scan network';}
}
async function save() {
  $('save').disabled=true;
  try {
    const saved=await api('config',config); config.revision=saved.revision; dirty=false; $('savebar').hidden=true;
    config=await api('config'); renderInterfaces(); toast('Configuration saved permanently. Restart to apply.'); await refresh();
  }catch(e){toast(e.message);}finally{$('save').disabled=false;}
}
document.addEventListener('click',async event=>{
  const b=event.target.closest('button');if(!b)return;
  if(b.dataset.page)navigate(b.dataset.page);
  if(b.dataset.add)openEditor({},b.dataset.add);
  if(b.dataset.edit)openEditor(config.interfaces.find(i=>i.id===b.dataset.edit));
  if(b.dataset.remove){config.interfaces=config.interfaces.filter(i=>i.id!==b.dataset.remove);changed();renderInterfaces();}
  if(b.dataset.move){const list=config.interfaces.filter(i=>i.role==='fallback');const item=list.find(i=>i.id===b.dataset.id);const other=list[list.indexOf(item)+Number(b.dataset.move)];if(other){const a=config.interfaces.indexOf(item),c=config.interfaces.indexOf(other);[config.interfaces[a],config.interfaces[c]]=[config.interfaces[c],config.interfaces[a]];changed();renderInterfaces();}}
  if(b.dataset.discovered!==undefined)openEditor(discoveries[Number(b.dataset.discovered)],b.dataset.role);
  if(b.dataset.select){try{await api('select',{id:b.dataset.select});toast('Switch requested. Automatic failback still follows your settings.');}catch(e){toast(e.message);}}
});
$('i-type').addEventListener('change',editorType);$('i-secure').addEventListener('change',editorType);
$('editor-form').addEventListener('submit',event=>{
  event.preventDefault();const item={id:editing||('iface-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,6))};
  document.querySelectorAll('#editor-form [data-field]').forEach(el=>{const key=el.dataset.field;if((key.includes('password')||key==='knx_address'||key==='client_address')&&!el.value)return;item[key]=el.type==='checkbox'?el.checked:el.type==='number'?Number(el.value):key.includes('password')?el.value:el.value.trim();});
  if(item.type==='usb'){if(item.device===openEditor.device)Object.assign(item,openEditor.identity);for(const key of ['host','port','protocol','secure','user_id','device_password','user_password'])delete item[key];}
  else {for(const key of ['device','mode','baud','extra_args','knx_address','client_address'])delete item[key];}
  if(editing){const index=config.interfaces.findIndex(i=>i.id===editing);config.interfaces[index]=item;}else config.interfaces.push(item);
  changed();renderInterfaces();$('editor').close();navigate('interfaces');
});
$('editor-cancel').onclick=()=>$('editor').close();$('scan-ip').onclick=()=>scan('ip');$('scan-usb').onclick=()=>scan('usb');$('save').onclick=save;
$('probe').onclick=async()=>{try {if(!$('i-host').value.trim())throw new Error('Enter an address first');$('probe').disabled=true;const d=await api('health',{host:$('i-host').value.trim(),port:Number($('i-port').value)});$('probe-result').textContent=d.reachable?'KNX description responded. Tunnel capacity and credentials are checked when connecting.':'No KNX response. Check address, power and network.';}catch(e){$('probe-result').textContent=e.message;}finally{$('probe').disabled=false;}};
document.querySelectorAll('[data-setting]').forEach(el=>el.addEventListener('change',()=>{config[el.dataset.setting]=el.type==='checkbox'?el.checked:el.type==='number'?Number(el.value):el.value;changed();}));
$('restart').onclick=async()=>{if(dirty){toast('Save your changes before restarting.');return;}if(!confirm('Apply saved configuration by restarting? Home Assistant sessions will reconnect.'))return;try{await api('restart',{});toast('Restart requested. This page will reconnect automatically.');}catch(e){toast(e.message);}};
$('discard').onclick=async()=>{try{config=await api('config');dirty=false;$('savebar').hidden=true;fillSettings();renderInterfaces();}catch(e){toast(e.message);}};
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
(async()=>{try{config=await api('config');renderInterfaces();fillSettings();await refresh();setInterval(refresh,3000);}catch(e){$('load-error').hidden=false;$('load-error').textContent='Could not load configuration: '+e.message;}})();
