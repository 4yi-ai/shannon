const $ = (id) => document.getElementById(id);
const labels = {queued:'排队中',preparing:'准备中',running:'运行中',recovering:'清理中',cancelling:'取消中',completed:'完成',partial:'部分完成',failed:'失败',cancelled:'已取消'};
const phases={preflight:'启动检查','auth-validation':'验证登录','pre-recon':'初步侦察',recon:'目标侦察',analysis:'漏洞分析',exploitation:'漏洞验证',report:'报告生成'};
$('zip').onchange=()=>{$('filename').textContent=$('zip').files[0]?.name||'尚未选择文件';};
let token = '', config = null, selected = null, sourceType = 'zip', offset = 0, timer = null;
function node(tag, text, className) { const element = document.createElement(tag); if(text !== undefined) element.textContent = text; if(className) element.className = className; return element; }
function notice(text, error=false) { $('notice').textContent=text; $('notice').className=error?'error':''; }
async function api(path, body) {
  const response = await fetch('/api/v1'+path, {method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
  if (!response.ok) { let message; try { message=(await response.json()).error; } catch { message='服务暂时不可用'; } throw new Error(message||'请求失败'); }
  return response;
}
function badge(state) { return node('span', labels[state]||state, 'badge '+state); }
function switchSource(type) { sourceType=type; $('zip-source').hidden=type!=='zip'; $('git-source').hidden=type!=='git'; $('zip-tab').setAttribute('aria-pressed',String(type==='zip')); $('git-tab').setAttribute('aria-pressed',String(type==='git')); $('repository').required=type==='git'; }
$('zip-tab').onclick=()=>switchSource('zip'); $('git-tab').onclick=()=>switchSource('git');
$('connect').onsubmit=async(event)=>{ event.preventDefault(); token=$('token').value; clearTimeout(timer); try { config=await (await api('/config')).json(); $('token').value=''; $('connection-status').textContent='已连接（已认证）'; $('submit').disabled=!config.execution_enabled; notice(config.execution_enabled?'授权目标：'+config.authorized_origins.join('、')+' · 模型：'+config.model:'执行尚未开放：等待操作员验证网络隔离并配置授权目标。可查看历史记录。'); await refresh(); } catch(error) { token=''; config=null; $('submit').disabled=true; $('connection-status').textContent='连接失败'; notice(error.message,true); } };
async function refresh() {
  if(!token) return;
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
  const root=$('detail');root.replaceChildren(); const dl=node('dl');
  const add=(title,value)=>{dl.append(node('dt',title),node('dd',value));};
  add('目标网站',task.target); const state=node('dd');state.append(badge(task.state));dl.append(node('dt','任务状态'),state);
  const progress=task.progress||{}; add('当前阶段',phases[progress.currentPhase]||progress.currentPhase||labels[task.state]);
  const total=progress.expectedAgents?.length||0, done=(progress.completedAgents?.length||0)+(progress.skippedAgents?.length||0);
  add('已处理 Agent',total?done+' / '+total:'等待进度信息');root.append(dl);
  const meter=node('progress');meter.max=total||1;meter.value=task.state==='completed'||task.state==='partial'?(total||1):Math.min(done,total||1);meter.setAttribute('aria-label','Agent 处理进度');root.append(meter);
  if(task.error)root.append(node('p',task.error,'message'));
  for(const reason of task.result?.partialReasons||[])root.append(node('p',reason.message||reason.code,'message'));
  const actions=node('div',undefined,'actions'); const cancel=node('button','取消任务');cancel.disabled=['completed','partial','failed','cancelled','cancelling'].includes(task.state);cancel.onclick=async()=>{try{await api('/tasks/'+task.id+'/cancel',{});await refresh();}catch(error){notice(error.message,true);}};actions.append(cancel);
  for(const [type,label] of [['markdown','下载 Markdown'],['pdf','下载 PDF']]){const button=node('button',label,'download');button.disabled=!task.reports?.[type];button.onclick=async()=>{try{const blob=await (await api('/tasks/'+task.id+'/reports/'+type)).blob();const url=URL.createObjectURL(blob);const link=node('a');link.href=url;link.download='Security-Assessment-Report.'+(type==='pdf'?'pdf':'md');link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){notice(error.message,true);}};actions.append(button);}root.append(actions);
}
async function encodeFile(file){const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=32768)binary+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(binary);}
$('create').onsubmit=async(event)=>{event.preventDefault();if(!config?.execution_enabled)return;$('submit').disabled=true;try{const body={target:$('target').value,source_type:sourceType,authorization_confirmed:$('authorized').checked};if(sourceType==='zip'){const file=$('zip').files[0];if(!file||file.size>32*1024*1024)throw new Error('请选择不超过 32 MiB 的 ZIP 文件');body.zip_base64=await encodeFile(file);}else{body.repository=$('repository').value;body.branch=$('branch').value;}const task=await(await api('/tasks',body)).json();selected=task.id;offset=0;notice('任务已创建，正在异步处理。');await refresh();}catch(error){notice(error.message,true);}finally{$('submit').disabled=!config?.execution_enabled;}};
