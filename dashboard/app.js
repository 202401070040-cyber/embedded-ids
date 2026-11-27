const REFRESH_MS = 3000;
let trafficChart = null, severityChart = null, latestAlerts = [], activeAlertId = null;
let knownAlertIds = new Set(), firstLoad = true, refreshBusy = false;
const $ = id => document.getElementById(id);
const esc = v => String(v ?? "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const parseJSON = v => { if (v && typeof v === "object") return v; try{return JSON.parse(v||"{}")}catch{return {}} };
const IST_ZONE = "Asia/Kolkata";
const parseIST = v => {
  if (!v) return null;
  const raw = String(v).trim();
  const isNaiveIST = /^\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}$/.test(raw);
  const normalized = raw.replace(" ", "T");
  const d = new Date(isNaiveIST ? normalized + "+05:30" : normalized);
  return Number.isNaN(d.getTime()) ? null : d;
};
const time = v => {
  if (!v) return "—";
  const d = parseIST(v);
  return d ? d.toLocaleString("en-IN", {
    timeZone: IST_ZONE, day:"2-digit", month:"short", year:"numeric",
    hour:"2-digit", minute:"2-digit", second:"2-digit", hour12:false
  }) : esc(v);
};
const shortTime = v => {
  if (!v) return "—";
  const d = parseIST(v);
  return d ? d.toLocaleTimeString("en-IN", {
    timeZone: IST_ZONE, hour:"2-digit", minute:"2-digit",
    second:"2-digit", hour12:false
  }) : esc(v);
};
const updateLiveClock = () => {
  const now = new Date();
  const clock = $("liveClock");
  const date = $("liveDate");
  if (clock) clock.textContent = now.toLocaleTimeString("en-IN", {
    timeZone: IST_ZONE, hour:"2-digit", minute:"2-digit",
    second:"2-digit", hour12:false
  });
  if (date) date.textContent = now.toLocaleDateString("en-IN", {
    timeZone: IST_ZONE, weekday:"long", day:"2-digit",
    month:"long", year:"numeric"
  });
};
updateLiveClock();
setInterval(updateLiveClock, 1000);
async function api(path, options={}) {
  const response = await fetch(path,{headers:{"Content-Type":"application/json",...(options.headers||{})},...options});
  const data = await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}
function toast(message,error=false){
  const el=document.createElement("div");el.className=`toast${error?" error":""}`;el.textContent=message;
  $("toastRegion").appendChild(el);setTimeout(()=>el.remove(),4200);
}
function setSource(id,ok,label){
  const el=$(id);if(!el)return;el.classList.toggle("off",!ok);el.innerHTML=`<i></i> ${esc(label)}`;
}
function setConnection(ok){
  $("connectionText").textContent=ok?"SENSOR API CONNECTED":"SENSOR API DISCONNECTED";
  $("connectionText").parentElement.style.color=ok?"#7cddb0":"#ff929b";
  setSource("apiStatus",ok,ok?"Connected":"Offline");
  setSource("statusApi",ok,ok?"Operational":"Offline");
  setSource("databaseStatus",ok,ok?"Connected":"Unavailable");
  setSource("statusDb",ok,ok?"Connected":"Unavailable");
}
function updateMetrics(summary,analytics,devices){
  $("totalAlerts").textContent=Number(summary.total_alerts||0).toLocaleString();
  $("criticalAlerts").textContent=Number(analytics.critical_high_open||0).toLocaleString();
  $("openIncidents").textContent=Number(analytics.open_incidents||0).toLocaleString();
  $("totalDevices").textContent=Number(summary.total_devices||0).toLocaleString();
  $("threatsBlocked").textContent=Number(analytics.threats_blocked||0).toLocaleString();
  $("newAlertsMetric").textContent=Number(analytics.new_alerts||0).toLocaleString();
  $("navNewCount").textContent=Number(analytics.new_alerts||0);
  $("notificationCount").textContent=Number(analytics.new_alerts||0);
  $("severityTotal").textContent=Number(analytics.total_alerts||0).toLocaleString();
  setSource("engineStatus",true,"Operational");
  setSource("statusEngine",true,"Operational");
}
function renderSeverity(analytics){
  const order=["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"], colors=["#ed4b59","#f59a38","#eab84e","#398ff0","#9aa9bd"];
  const counts=order.map(k=>Number((analytics.severity||{})[k]||0));
  $("severityLegend").innerHTML=order.map((name,i)=>`<div class="legend-row"><i style="background:${colors[i]}"></i><span>${name.charAt(0)+name.slice(1).toLowerCase()}</span><b>${counts[i]}</b></div>`).join("");
  if(typeof Chart==="undefined")return;
  if(severityChart)severityChart.destroy();
  severityChart=new Chart($("severityChart"),{type:"doughnut",data:{labels:order,datasets:[{data:counts,backgroundColor:colors,borderColor:"#101b2c",borderWidth:3,hoverOffset:5}]},options:{responsive:true,maintainAspectRatio:false,cutout:"70%",plugins:{legend:{display:false},tooltip:{backgroundColor:"#081323"}}}});
}
function renderTrafficChart(analytics){
  if(typeof Chart==="undefined")return;
  const entries=Object.entries(analytics.protocols||{});const colors=["#318cf1","#34c5d5","#a16df5","#eab84e","#ed5968","#8b9db4"];
  if(trafficChart)trafficChart.destroy();
  trafficChart=new Chart($("trafficChart"),{type:"bar",data:{labels:entries.map(x=>x[0]),datasets:[{data:entries.map(x=>x[1]),backgroundColor:entries.map((_,i)=>colors[i%colors.length]),borderRadius:4,maxBarThickness:28}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:"#91a2b8",font:{size:12}},grid:{display:false}},y:{beginAtZero:true,ticks:{color:"#8193a8",font:{size:12},precision:0},grid:{color:"#25364d"}}}}});
}
function badgeSeverity(s){const v=String(s||"LOW").toUpperCase();return `<span class="severity-badge severity-${esc(v)}">${esc(v)}</span>`}
function badgeStatus(s){const v=String(s||"NEW").toUpperCase();return `<span class="status-badge status-${esc(v)}">${esc(v)}</span>`}
function alertRow(a,queue=false){
  const id=Number(a.id), title=String(a.alert_type||"Security alert").replaceAll("_"," ");
  if(queue)return `<tr class="alert-row" data-alert-id="${id}" tabindex="0"><td><b class="alert-title">${esc(title)}</b><small class="alert-sub">${esc(a.description)}</small></td><td>${badgeSeverity(a.severity)}</td><td class="mono">${esc(a.source_ip)}</td><td class="mono">${esc(a.destination_ip)}</td><td>${badgeStatus(a.status)}</td><td class="mono">${shortTime(a.timestamp)}</td><td><a class="open-link">Inspect →</a></td></tr>`;
  return `<tr class="alert-row" data-alert-id="${id}"><td class="mono">${shortTime(a.timestamp)}</td><td><b class="alert-title">${esc(title)}</b><small class="alert-sub">${esc(a.description)}</small></td><td>${badgeSeverity(a.severity)}</td><td class="mono">${esc(a.source_ip)}</td><td class="mono">${esc(a.destination_ip)}</td><td>${badgeStatus(a.status)}</td><td><a class="open-link">View</a></td></tr>`;
}
function renderAlerts(alerts){
  latestAlerts=alerts;
  const search=$("alertSearch").value.trim().toLowerCase(), status=$("statusFilter").value, severity=$("severityFilter").value;
  const visible=alerts.filter(a=>{
    const hay=[a.alert_type,a.description,a.source_ip,a.destination_ip].join(" ").toLowerCase();
    return (!search||hay.includes(search))&&(!status||String(a.status||"NEW").toUpperCase()===status)&&(!severity||String(a.severity||"").toUpperCase()===severity);
  });
  $("queueCount").textContent=visible.length;
  $("alertTableFoot").textContent=`Showing ${visible.length} of ${alerts.length} most recent alerts`;
  $("alertsTable").innerHTML=visible.length?visible.map(a=>alertRow(a,true)).join():'<tr><td colspan="7" class="empty">No alerts match these filters.</td></tr>';
  $("recentAlerts").innerHTML=alerts.length?alerts.slice(0,5).map(a=>alertRow(a,false)).join():'<tr><td colspan="7" class="empty">No IDS alerts have been recorded yet. Detection events will appear here when rules trigger.</td></tr>';
  const open=alerts.filter(a=>String(a.status||"NEW").toUpperCase()!=="RESOLVED").slice(0,4);
  $("recentCases").innerHTML=open.length?open.map(a=>`<div class="case-row alert-row" data-alert-id="${Number(a.id)}"><div><b>${esc(String(a.alert_type||"Alert").replaceAll("_"," "))}</b><small>#ALERT-${String(a.id).padStart(4,"0")} · ${esc(a.source_ip)}</small></div><div class="case-right">${badgeSeverity(a.severity)}<small>${esc(a.status||"NEW")}</small></div></div>`).join():'<div class="empty">No open alerts or cases.</div>';
  document.querySelectorAll("[data-alert-id]").forEach(row=>row.addEventListener("click",()=>openIncident(Number(row.dataset.alertId))));
}
function renderSources(analytics){
  const rows=analytics.top_sources||[];
  $("topSources").innerHTML=rows.length?rows.map((r,i)=>`<div class="rank-row"><div class="rank-label"><span>${esc(r.source_ip)}</span><b>${r.count}</b></div><div class="rank-bar"><span style="width:${Math.max(5,100*r.count/Math.max(...rows.map(x=>x.count),1))}%"></span></div></div>`).join():'<div class="empty">No alert sources recorded.</div>';
}
function renderDevices(devices){
  $("devicesTable").innerHTML=devices.length?devices.slice(0,8).map(d=>`<tr><td class="mono">${esc(d.ip_address)}</td><td class="mono">${esc(d.mac_address||"—")}</td><td>${shortTime(d.first_seen)}</td><td>${shortTime(d.last_seen)}</td></tr>`).join():'<tr><td colspan="4" class="empty">No observed endpoints yet.</td></tr>';
}
function renderEvents(events){
  $("eventFeed").innerHTML=events.length?events.slice(0,6).map(e=>`<div class="event-row"><i class="event-icon"></i><div><b>${esc(e.event_type)} · ${esc(e.severity)}</b><small>${esc(e.message)}<br>${time(e.timestamp)}</small></div></div>`).join():'<div class="empty">No system events recorded.</div>';
}
function renderPackets(packets){
  $("trafficTable").innerHTML=packets.length?packets.slice(0,10).map(p=>`<tr><td>${shortTime(p.timestamp)}</td><td class="mono">${esc(p.src_ip)}</td><td class="mono">${esc(p.dst_ip)}</td><td>${esc(p.protocol)}</td><td class="mono">${esc(p.src_port)}</td><td class="mono">${esc(p.dst_port)}</td><td>${esc(p.packet_length)}</td></tr>`).join():'<tr><td colspan="7" class="empty">No captured packets available.</td></tr>';
}
function renderPacketStats(stats){
  $("packetsReceived").textContent=Number(stats.packets_received||0).toLocaleString();
  $("packetsExamined").textContent=Number(stats.packets_examined||0).toLocaleString();
  $("examinationRate").textContent=`${Number(stats.examination_rate||0).toFixed(2)}%`;
}
async function refreshDashboard(showError=false){
  if(refreshBusy)return;refreshBusy=true;
  try{
    const [health,system,summary,analytics,alerts,packets,devices,events,packetStats]=await Promise.all([
      api("/health"),api("/api/system-status"),api("/api/summary"),api("/api/analytics"),api("/api/alerts?limit=100"),
      api("/api/traffic?limit=500"),api("/api/devices"),api("/api/events?limit=30"),api("/api/packet-stats")
    ]);
    setConnection(health.status==="healthy");
    updateMetrics(summary,analytics,devices);renderSeverity(analytics);renderTrafficChart(analytics);
    renderAlerts(alerts);renderSources(analytics);renderDevices(devices);renderEvents(events);renderPackets(packets);renderPacketStats(packetStats);
    const current=new Set(alerts.map(a=>Number(a.id)));
    if(!firstLoad){
      const fresh=alerts.filter(a=>!knownAlertIds.has(Number(a.id)));
      fresh.slice(0,3).forEach(a=>{
        toast(`New ${a.severity} alert: ${String(a.alert_type).replaceAll("_"," ")}`);
        if("Notification"in window&&Notification.permission==="granted")new Notification("SOC Sentinel — New IDS alert",{body:`${a.alert_type} · ${a.source_ip} → ${a.destination_ip}`});
      });
    }
    knownAlertIds=current;firstLoad=false;
    $("lastUpdated").textContent=new Date().toLocaleTimeString("en-IN",{timeZone:IST_ZONE,hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false});
  }catch(e){setConnection(false);if(showError)toast(`Dashboard refresh failed: ${e.message}`,true);console.error(e)}
  finally{refreshBusy=false}
}
function detailBox(label,value){return `<div class="detail-box"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`}
async function openIncident(id){
  activeAlertId=id;$("incidentModal").classList.remove("hidden");$("modalContent").innerHTML='<div class="empty">Loading alert details…</div>';$("modalActions").innerHTML="";
  try{
    const a=await api(`/api/alerts/${id}`),evidence=parseJSON(a.evidence||a.evidence_json),activity=a.activity||await api(`/api/alerts/${id}/activity`);
    $("modalTitle").textContent=`${String(a.alert_type||"Security alert").replaceAll("_"," ")} · #${a.id}`;
    $("modalContent").innerHTML=`<div class="detail-grid">${detailBox("SEVERITY",a.severity)}${detailBox("STATUS",a.status||"NEW")}${detailBox("SOURCE IP",a.source_ip)}${detailBox("DESTINATION IP",a.destination_ip)}${detailBox("FIRST DETECTED",time(a.timestamp))}${detailBox("LAST UPDATED",time(a.updated_at))}</div>
      <div class="detail-section"><h3>Detection description</h3><p class="detail-description">${esc(a.description)}</p></div>
      <div class="detail-section"><h3>Detection evidence</h3><pre class="evidence-json">${esc(JSON.stringify(evidence,null,2))}</pre></div>
      <div class="detail-section"><h3>Investigation notes</h3><textarea class="notes-input" id="investigationNotes" placeholder="Record findings and next steps…">${esc(a.investigation_notes||"")}</textarea></div>
      <div class="detail-section"><h3>Resolution details</h3><textarea class="notes-input" id="resolutionNotes" placeholder="Required when resolving this alert…">${esc(a.resolution||"")}</textarea></div>
      <div class="detail-section"><h3>Activity history</h3>${activity.length?activity.map(x=>`<div class="activity-item"><strong>${esc(x.action)} · ${esc(x.actor)}</strong><small>${time(x.timestamp)} — ${esc(x.details)}</small></div>`).join(""):'<p class="detail-description">No activity recorded.</p>'}</div>`;
    const state=String(a.status||"NEW").toUpperCase(),buttons=[];
    if(state==="NEW")buttons.push('<button class="action-button primary" data-action="ACKNOWLEDGED">Acknowledge</button>');
    if(state==="NEW"||state==="ACKNOWLEDGED")buttons.push('<button class="action-button" data-action="INVESTIGATING">Start investigation</button>');
    if(state!=="RESOLVED")buttons.push('<button class="action-button resolve" data-action="RESOLVED">Resolve alert</button>');
    if(state!=="NEW")buttons.push('<button class="action-button" data-action="NEW">Reopen</button>');
    $("modalActions").innerHTML=buttons.join("")+'<button class="action-button" id="saveNotesButton">Save notes</button>';
    $("modalActions").querySelectorAll("[data-action]").forEach(b=>b.addEventListener("click",()=>changeStatus(b.dataset.action)));
    $("saveNotesButton").addEventListener("click",saveNotes);
  }catch(e){$("modalContent").innerHTML=`<p class="detail-description">Unable to load alert: ${esc(e.message)}</p>`;toast(e.message,true)}
}
async function saveNotes(){
  if(!activeAlertId)return;
  try{const current=await api(`/api/alerts/${activeAlertId}`);await api(`/api/alerts/${activeAlertId}/status`,{method:"PATCH",body:JSON.stringify({status:current.status||"NEW",actor:"local-analyst",notes:$("investigationNotes").value})});toast("Investigation notes saved");await refreshDashboard();await openIncident(activeAlertId)}
  catch(e){toast(e.message,true)}
}
async function changeStatus(status){
  if(!activeAlertId)return;
  const notes=$("investigationNotes")?.value||null,resolution=$("resolutionNotes")?.value?.trim()||null;
  if(status==="RESOLVED"&&!resolution){toast("Add resolution details before resolving this alert.",true);$("resolutionNotes").focus();return}
  try{await api(`/api/alerts/${activeAlertId}/status`,{method:"PATCH",body:JSON.stringify({status,actor:"local-analyst",notes,resolution})});toast(`Alert #${activeAlertId} updated: ${status}`);await refreshDashboard();await openIncident(activeAlertId)}
  catch(e){toast(e.message,true)}
}
function closeModal(){$("incidentModal").classList.add("hidden");activeAlertId=null}
$("alertSearch").addEventListener("input",()=>renderAlerts(latestAlerts));
$("statusFilter").addEventListener("change",()=>renderAlerts(latestAlerts));
$("severityFilter").addEventListener("change",()=>renderAlerts(latestAlerts));
$("clearFilters").addEventListener("click",()=>{$("alertSearch").value="";$("statusFilter").value="";$("severityFilter").value="";renderAlerts(latestAlerts)});
$("refreshButton").addEventListener("click",()=>refreshDashboard(true));
$("closeModal").addEventListener("click",closeModal);
$("incidentModal").addEventListener("click",e=>{if(e.target===$("incidentModal"))closeModal()});
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeModal()});
$("notifyButton").addEventListener("click",async()=>{if(!("Notification"in window))return toast("Browser notifications are not supported.",true);const p=await Notification.requestPermission();toast(p==="granted"?"Browser notifications enabled.":"Notification permission not granted.",p!=="granted")});
document.addEventListener("DOMContentLoaded",()=>{refreshDashboard(true);setInterval(refreshDashboard,REFRESH_MS)});
