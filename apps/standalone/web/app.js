const $ = (id) => document.getElementById(id);
const labels = {queued:'排队中',preparing:'准备中',running:'运行中',waiting_for_code:'等待邮箱验证码',recovering:'清理中',cancelling:'取消中',completed:'完成',partial:'部分完成',failed:'失败',cancelled:'已取消'};
const phases={preflight:'启动检查','auth-validation':'验证登录','pre-recon':'初步侦察',recon:'目标侦察',analysis:'漏洞分析',exploitation:'漏洞验证',report:'报告生成'};
$('zip').onchange=()=>{uploadedZip={file:null,id:null};$('filename').textContent=$('zip').files[0]?.name||'尚未选择文件';};
let uploadedZip = {file:null,id:null};
let emailDraft = {id:null,value:''};
let config = null, selected = null, sourceType = 'zip', offset = 0, timer = null;
function node(tag, text, className) { const element = document.createElement(tag); if(text !== undefined) element.textContent = text; if(className) element.className = className; return element; }
function notice(text, error=false) { $('notice').textContent=text; $('notice').className=error?'error':''; }
async function api(path, body) {
  const response = await fetch('/api/v1'+path, {method:body===undefined?'GET':'POST',credentials:'same-origin',headers:{...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
  if (!response.ok) { let message; try { message=(await response.json()).error; } catch { message='服务暂时不可用'; } throw new Error(message||'请求失败'); }
  return response;
}
function badge(state) { return node('span', labels[state]||state, 'badge '+state); }
function switchSource(type) { sourceType=type; $('zip-source').hidden=type!=='zip'; $('git-source').hidden=type!=='git'; $('zip-tab').setAttribute('aria-pressed',String(type==='zip')); $('git-tab').setAttribute('aria-pressed',String(type==='git')); $('repository').required=type==='git'; }
$('login-email-code').onchange=()=>{const manual=$('login-email-code').checked;$('login-totp').disabled=manual;if(manual)$('login-totp').value='';};
$('login-enabled').onchange=()=>{const enabled=$('login-enabled').checked;$('login-fields').hidden=!enabled;for(const id of ['login-url','login-username','login-password','login-flow','login-success'])$(id).required=enabled;if(!enabled){$('login-password').value='';$('login-totp').value='';}};
$('zip-tab').onclick=()=>switchSource('zip'); $('git-tab').onclick=()=>switchSource('git');
async function connect() {
  clearTimeout(timer);
  try {
    config=await (await api('/config')).json();
    $('connection-status').textContent='4YI 已登录';
    $('submit').disabled=!config.execution_enabled;
    notice(config.execution_enabled?(config.execution_mode==='trusted_dev'?'开发内测 · ':'')+(config.target_policy==='public_https'?'目标范围：页面填写并确认授权的公网 HTTPS 网站':'授权目标：'+config.authorized_origins.join('、'))+' · 模型：'+config.model:'扫描执行未启用。请检查本实例的执行模式和开关；仍可查看历史记录。');
    await refresh();
  } catch(error) {
    config=null; $('submit').disabled=true;
    $('connection-status').textContent='登录验证未完成';
    notice(error.message,true);
  }
}
$('reconnect').onclick=connect;
async function refresh() {
  if(!config) return;
  try {
    const data=await (await api('/tasks?limit=20&offset='+offset)).json();
    $('tasks').replaceChildren();
    for(const task of data.tasks) {
      const row=node('tr'); if(selected===task.id) row.className='selected';
      const target=node('td'); const choose=node('button',task.target,'task-select'); choose.onclick=()=>{selected=task.id;refresh();}; target.append(choose);
      const state=node('td'); state.append(badge(task.state)); row.append(target,state,node('td',new Date(task.created*1000).toLocaleString('zh-CN'))); $('tasks').append(row);
    }
    if(!data.tasks.length) { const cell=node('td','暂无扫描任务','empty');cell.colSpan=3;const row=node('tr');row.append(cell);$('tasks').append(row); }
    $('previous').disabled=offset===0; $('next').disabled=data.tasks.length<20;
    if(selected) renderDetail(await (await api('/tasks/'+selected)).json());
  } catch(error) { notice(error.message,true); }
  clearTimeout(timer); timer=setTimeout(refresh,4000);
}
$('refresh').onclick=refresh;
$('previous').onclick=()=>{offset=Math.max(0,offset-20);refresh();}; $('next').onclick=()=>{offset+=20;refresh();};
function renderDetail(task) {
  const focused=document.activeElement?.id==='email-code';const selection=focused?document.activeElement.selectionStart:null;
  const root=$('detail');root.replaceChildren();
  const challenge=task.email_challenge;
  if(challenge && (challenge.deadline_at||challenge.expires_at)*1000>Date.now()){
    if(emailDraft.id!==challenge.id)emailDraft={id:challenge.id,value:''};
    const form=node('form',undefined,'email-verification');
    const expired=challenge.expires_at*1000<=Date.now();
    const attempt=challenge.attempt||1, maximum=challenge.max_attempts||3;
    const hints={initial:'请到测试账号邮箱查看本次验证码。',incorrect:'网站未接受上次验证码，请重新输入。',after_resend:'请查看重新发送的邮件，并填写最新验证码。'};
    form.append(node('h4','等待邮箱验证码 · 第 '+attempt+' / '+maximum+' 轮'),node('p',challenge.submitted?'验证码或重发请求已提交，正在处理。':hints[challenge.reason]||hints.initial));
    form.append(node('p','当前验证码输入截止：'+new Date(challenge.expires_at*1000).toLocaleTimeString('zh-CN')+' · 登录等待截止：'+new Date((challenge.deadline_at||challenge.expires_at)*1000).toLocaleTimeString('zh-CN')));
    if(!challenge.submitted){
      if(!expired){
        const label=node('label','邮箱验证码');label.htmlFor='email-code';
        const input=node('input');input.id='email-code';input.type='password';input.autocomplete='one-time-code';input.inputMode='numeric';input.minLength=4;input.maxLength=12;input.pattern='[A-Za-z0-9]{4,12}';input.required=true;input.value=emailDraft.value;
        input.oninput=()=>{emailDraft={id:challenge.id,value:input.value};};
        const button=node('button','提交验证码并继续');button.type='submit';form.append(label,input,button);
        form.onsubmit=async(event)=>{event.preventDefault();button.disabled=true;try{await (await api('/tasks/'+task.id+'/email-code',{request_id:challenge.id,code:input.value.trim()})).json();input.value='';emailDraft={id:null,value:''};notice('验证码已提交，正在继续登录验证。');await refresh();}catch(error){notice(error.message,true);button.disabled=false;}};
      }else{form.append(node('p',attempt<maximum?'本轮输入已超时，可以请求重新发送验证码。':'最后一轮输入已超时，任务将停止。'));emailDraft={id:null,value:''};}
      if(attempt<maximum){
        const seconds=Math.max(0,Math.ceil(((challenge.resend_after||challenge.expires_at)*1000-Date.now())/1000));
        const resend=node('button',seconds?'重新发送（'+seconds+' 秒后）':'请求重新发送验证码');resend.type='button';resend.disabled=seconds>0;
        resend.onclick=async()=>{resend.disabled=true;try{await (await api('/tasks/'+task.id+'/email-resend',{request_id:challenge.id})).json();emailDraft={id:null,value:''};notice('已请求在当前登录会话中重新发送邮件，等待网站确认。');await refresh();}catch(error){notice(error.message,true);resend.disabled=false;}};
        form.append(resend);
      }else{form.append(node('p','已到最后一轮，请确认验证码后提交。'));}
    }else{emailDraft={id:null,value:''};}
    root.append(form);
    if(focused && !challenge.submitted && !expired){const input=form.querySelector('input');input.focus({preventScroll:true});if(selection!==null)input.setSelectionRange(selection,selection);}
  }else{emailDraft={id:null,value:''};} const dl=node('dl');
  const add=(title,value)=>{dl.append(node('dt',title),node('dd',value));};
  add('目标网站',task.target); add('登录测试',task.authenticated_scan?'已配置专用测试账号':'未配置'); const state=node('dd');state.append(badge(task.state));dl.append(node('dt','任务状态'),state);
  const progress=task.progress||{}; add('当前阶段',phases[progress.currentPhase]||progress.currentPhase||labels[task.state]);
  const total=progress.expectedAgents?.length||0, done=(progress.completedAgents?.length||0)+(progress.skippedAgents?.length||0);
  add('已处理 Agent',total?done+' / '+total:'等待进度信息');root.append(dl);
  const meter=node('progress');meter.max=total||1;meter.value=task.state==='completed'||task.state==='partial'?(total||1):Math.min(done,total||1);meter.setAttribute('aria-label','Agent 处理进度');root.append(meter);
  if(task.error)root.append(node('p',task.error,'message'));
  for(const reason of task.result?.partialReasons||[])root.append(node('p',reason.message||reason.code,'message'));
  const actions=node('div',undefined,'actions'); const cancel=node('button','取消任务');cancel.disabled=['completed','partial','failed','cancelled','cancelling'].includes(task.state);cancel.onclick=async()=>{try{await api('/tasks/'+task.id+'/cancel',{});await refresh();}catch(error){notice(error.message,true);}};actions.append(cancel);
  for(const [type,label] of [['markdown','下载 Markdown'],['pdf','下载 PDF']]){const button=node('button',label,'download');button.disabled=!task.reports?.[type];button.onclick=async()=>{try{const blob=await (await api('/tasks/'+task.id+'/reports/'+type)).blob();const url=URL.createObjectURL(blob);const link=node('a');link.href=url;link.download='Security-Assessment-Report.'+(type==='pdf'?'pdf':'md');link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){notice(error.message,true);}};actions.append(button);}root.append(actions);
}
async function uploadZip(file){
  if(uploadedZip.file===file && uploadedZip.id)return uploadedZip.id;
  notice('正在上传源码 ZIP（'+(file.size/1024/1024).toFixed(1)+' MiB），请稍候…');
  const response=await fetch('/api/v1/uploads',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/zip'},body:file});
  if(!response.ok){let message;try{message=(await response.json()).error;}catch{message=response.status===413?'上传被入口拒绝，请检查入口的文件大小限制。':'源码上传失败，请重试。';}throw new Error(message);}
  const result=await response.json();uploadedZip={file,id:result.upload_id};return result.upload_id;
}
$('create').onsubmit=async(event)=>{event.preventDefault();if(!config?.execution_enabled)return;$('submit').disabled=true;try{const body={target:$('target').value,source_type:sourceType,authorization_confirmed:$('authorized').checked};if(sourceType==='zip'){const file=$('zip').files[0];if(!file||file.size>(config.max_zip_bytes||256*1024*1024))throw new Error('请选择不超过 256 MiB 的 ZIP 文件');body.upload_id=await uploadZip(file);}else{body.repository=$('repository').value;body.branch=$('branch').value;}if($('login-enabled').checked){body.authentication={manual_email_code:$('login-email-code').checked,login_type:'form',login_url:$('login-url').value,credentials:{username:$('login-username').value,password:$('login-password').value,...($('login-totp').value?{totp_secret:$('login-totp').value}: {})},login_flow:$('login-flow').value.split('\n').map(s=>s.trim()).filter(Boolean),success_condition:{type:$('login-success-type').value,value:$('login-success').value}};}notice('正在创建扫描任务…');const task=await(await api('/tasks',body)).json();uploadedZip={file:null,id:null};$('login-password').value='';$('login-totp').value='';selected=task.id;offset=0;notice('任务已创建，正在异步处理。');await refresh();}catch(error){if(error.message.includes('Uploaded ZIP'))uploadedZip={file:null,id:null};notice(error.message,true);}finally{$('submit').disabled=!config?.execution_enabled;}};

connect();
