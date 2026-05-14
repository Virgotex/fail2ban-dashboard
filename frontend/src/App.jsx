import { useState, useEffect, useCallback, useRef } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts'
import { ShieldCheck, ShieldOff, Activity, Lock, FileText, BarChart2, Settings, AlertTriangle, RefreshCw, Wifi, WifiOff, Trash2, Search, Terminal } from 'lucide-react'
import { api, createWebSocket } from './hooks/useApi'

const PIE_COLORS = ['#e24b4a','#f6ad55','#63b3ed','#48bb78','#9f7aea','#fc8181','#76e4f7']

// ─── Jail metadata (from your jail.local) ────────────────────────────────
const JAIL_META = {
  'recidive':         { severity:'CRITICAL', color:'#fc4444', intent:'Repeat multi-jail offender' },
  'scanner-bots':     { severity:'HIGH',     color:'#e24b4a', intent:'Automated vulnerability scanner' },
  'api-probes':       { severity:'HIGH',     color:'#e24b4a', intent:'Admin panel / credential probing' },
  'env-calls':        { severity:'HIGH',     color:'#e24b4a', intent:'Environment file harvesting (.env)' },
  'script-execution': { severity:'HIGH',     color:'#e24b4a', intent:'Remote code execution attempt' },
  'nginx-dos':        { severity:'MEDIUM',   color:'#f6ad55', intent:'DoS / rate-limit abuse' },
  'sshd':             { severity:'MEDIUM',   color:'#f6ad55', intent:'SSH brute-force' },
  'nginx-http-auth':  { severity:'MEDIUM',   color:'#f6ad55', intent:'HTTP auth brute-force' },
  'nginx-botsearch':  { severity:'MEDIUM',   color:'#f6ad55', intent:'Bot / directory scan' },
  'nginx-noscript':   { severity:'LOW',      color:'#63b3ed', intent:'Forbidden resource access' },
}
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','OBSERVED']

// ─── Shared UI ────────────────────────────────────────────────────────────
function Badge({ children, color='default' }) {
  const map = { default:{bg:'rgba(255,255,255,0.07)',fg:'#7d8fa3'}, green:{bg:'rgba(72,187,120,0.15)',fg:'#48bb78'}, red:{bg:'rgba(226,75,74,0.15)',fg:'#ff6b6b'}, amber:{bg:'rgba(246,173,85,0.15)',fg:'#f6ad55'}, blue:{bg:'rgba(99,179,237,0.15)',fg:'#63b3ed'} }
  const c = map[color]||map.default
  return <span style={{background:c.bg,color:c.fg,fontSize:10,fontWeight:500,padding:'2px 8px',borderRadius:20,fontFamily:'var(--mono)',whiteSpace:'nowrap'}}>{children}</span>
}

function Card({ children, style={} }) {
  return <div style={{background:'var(--bg2)',border:'0.5px solid var(--border)',borderRadius:'var(--radius-lg)',...style}}>{children}</div>
}

function SectionHeader({ icon:Icon, title, right }) {
  return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 16px',borderBottom:'0.5px solid var(--border)'}}>
      <div style={{display:'flex',alignItems:'center',gap:8,fontSize:12,fontWeight:600}}>
        {Icon && <Icon size={14} style={{color:'var(--text2)'}}/>}{title}
      </div>
      {right}
    </div>
  )
}

function StatusDot({ ok }) {
  return <span style={{width:7,height:7,borderRadius:'50%',background:ok?'var(--green)':'var(--accent)',display:'inline-block',animation:ok?'pulse 2s infinite':'none',flexShrink:0}}/>
}

function LoadingBox({ rows=4 }) {
  return (
    <div style={{padding:16,display:'flex',flexDirection:'column',gap:10}}>
      <style>{`@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}`}</style>
      {Array.from({length:rows}).map((_,i)=>(
        <div key={i} style={{height:14,borderRadius:4,background:'linear-gradient(90deg,var(--bg3) 25%,var(--border2) 50%,var(--bg3) 75%)',backgroundSize:'200% 100%',animation:'shimmer 1.4s infinite',width:`${60+(i*13)%40}%`,opacity:0.6}}/>
      ))}
    </div>
  )
}

function ErrorBox({ message, onRetry }) {
  return (
    <div style={{margin:16,padding:'12px 16px',background:'rgba(226,75,74,0.08)',border:'0.5px solid rgba(226,75,74,0.3)',borderRadius:'var(--radius)',display:'flex',alignItems:'center',justifyContent:'space-between',fontSize:12}}>
      <span style={{color:'#ff6b6b'}}><AlertTriangle size={12} style={{marginRight:6,verticalAlign:'middle'}}/>{message}</span>
      {onRetry && <button onClick={onRetry} style={{background:'none',border:'0.5px solid rgba(226,75,74,0.4)',borderRadius:'var(--radius)',color:'#ff6b6b',fontSize:11,padding:'3px 10px',cursor:'pointer'}}>Retry</button>}
    </div>
  )
}

// ─── Clickable IP ─────────────────────────────────────────────────────────
function ClickableIP({ ip, onInspect }) {
  return (
    <span
      onClick={() => onInspect(ip)}
      title={`Investigate ${ip}`}
      style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--blue)',cursor:'pointer',borderBottom:'1px dashed rgba(99,179,237,0.4)',transition:'color .12s'}}
      onMouseEnter={e=>e.currentTarget.style.color='#90cdf4'}
      onMouseLeave={e=>e.currentTarget.style.color='var(--blue)'}
    >{ip}</span>
  )
}

// ─── IP Investigation Modal ───────────────────────────────────────────────
function IPModal({ ip, onClose }) {
  const [data,    setData]    = useState(null)
  const [geo,     setGeo]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [tab,     setTab]     = useState('summary')

  useEffect(() => {
    if (!ip) return
    setLoading(true); setData(null); setGeo(null); setError(null); setTab('summary')
    Promise.all([
      api.ipDetails(ip),
      fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query`)
        .then(r=>r.json()).catch(()=>null),
    ])
      .then(([details, geoData]) => { setData(details); if (geoData?.status==='success') setGeo(geoData) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [ip])

  useEffect(() => {
    const h = e => { if (e.key==='Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  // Derive highest threat level from jails hit
  const threat = !data ? null : (() => {
    for (const sev of SEV_ORDER) {
      const match = data.jailsHit?.find(j => JAIL_META[j.name]?.severity === sev)
      if (match) return JAIL_META[match.name]
    }
    if (data.summary?.isRecurring) return { severity:'HIGH', color:'var(--accent2)', intent:'' }
    return { severity:'OBSERVED', color:'var(--text2)', intent:'' }
  })()

  const typeColor = t => t==='ban'?'var(--accent2)':t==='unban'?'var(--green)':t==='attempt'?'var(--amber)':'var(--text3)'
  const typeIcon  = t => t==='ban'?'':t==='unban'?'[OK]':t==='attempt'?'[*]':'[LOG]'

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose} style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.72)',backdropFilter:'blur(3px)',zIndex:1000}}/>

      {/* Modal */}
      <div style={{position:'fixed',top:'50%',left:'50%',transform:'translate(-50%,-50%)',width:740,maxWidth:'96vw',maxHeight:'90vh',background:'var(--bg2)',border:'0.5px solid var(--border2)',borderRadius:12,zIndex:1001,display:'flex',flexDirection:'column',overflow:'hidden',boxShadow:'0 24px 64px rgba(0,0,0,0.6)'}}>

        {/* Header */}
        <div style={{padding:'14px 18px',borderBottom:'0.5px solid var(--border)',display:'flex',alignItems:'center',justifyContent:'space-between',background:'var(--bg3)',flexShrink:0}}>
          <div style={{display:'flex',alignItems:'center',gap:12}}>
            <span style={{fontSize:12,color:'var(--text2)'}}>[INSPECT]</span>
            <div>
              <div style={{fontFamily:'var(--mono)',fontSize:15,fontWeight:700,color:'var(--blue)'}}>{ip}</div>
              <div style={{fontSize:11,color:'var(--text3)',marginTop:1}}>IP investigation report</div>
            </div>
            {threat && (
              <span style={{background:`${threat.color}22`,border:`0.5px solid ${threat.color}66`,color:threat.color,fontSize:10,fontWeight:700,fontFamily:'var(--mono)',padding:'3px 9px',borderRadius:4,letterSpacing:'.04em'}}>
                [!] {threat.severity}
              </span>
            )}
          </div>
          <button onClick={onClose} style={{background:'none',border:'none',color:'var(--text2)',cursor:'pointer',fontSize:14,padding:'2px 6px',lineHeight:1}}>×</button>
        </div>

        {/* Tabs */}
        <div style={{display:'flex',borderBottom:'0.5px solid var(--border)',padding:'0 18px',background:'var(--bg3)',flexShrink:0}}>
          {[['summary','Summary'],['timeline','Timeline'],['geo',' Geo & Intel']].map(([t,label])=>(
            <button key={t} onClick={()=>setTab(t)} style={{padding:'8px 14px',background:'none',border:'none',borderBottom:tab===t?'2px solid var(--accent)':'2px solid transparent',color:tab===t?'var(--text)':'var(--text2)',fontSize:12,fontWeight:tab===t?600:400,cursor:'pointer',fontFamily:'var(--sans)',marginBottom:-1}}>
              {label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div style={{flex:1,overflowY:'auto',padding:18}}>
          {loading ? <LoadingBox rows={6}/> : error ? <ErrorBox message={error}/> : !data ? null : (<>

            {/* SUMMARY */}
            {tab==='summary' && (
              <div style={{display:'flex',flexDirection:'column',gap:12}}>

                {/* Stats */}
                <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8}}>
                  {[
                    {label:'Total bans',      value:data.summary.totalBans,      color:data.summary.totalBans>0?'var(--accent2)':'var(--green)'},
                    {label:'Attempts found',  value:data.summary.totalAttempts,  color:'var(--amber)'},
                    {label:'Jails triggered', value:data.summary.jailCount,      color:'var(--blue)'},
                    {label:'Recurring',       value:data.summary.isRecurring?'YES':'No', color:data.summary.isRecurring?'var(--accent2)':'var(--text2)'},
                  ].map(m=>(
                    <div key={m.label} style={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:8,padding:'10px 12px'}}>
                      <div style={{fontSize:10,color:'var(--text3)',textTransform:'uppercase',letterSpacing:'.06em',marginBottom:4}}>{m.label}</div>
                      <div style={{fontSize:20,fontWeight:700,fontFamily:'var(--mono)',color:m.color}}>{m.value}</div>
                    </div>
                  ))}
                </div>

                {/* Activity window */}
                <div style={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:8,padding:'10px 14px'}}>
                  <div style={{fontSize:11,color:'var(--text2)',marginBottom:6,fontWeight:600,textTransform:'uppercase',letterSpacing:'.04em'}}>Activity window</div>
                  <div style={{display:'flex',gap:32,fontSize:12}}>
                    <div><span style={{color:'var(--text3)'}}>First seen: </span><span style={{fontFamily:'var(--mono)'}}>{data.summary.firstSeen||'—'}</span></div>
                    <div><span style={{color:'var(--text3)'}}>Last seen:  </span><span style={{fontFamily:'var(--mono)'}}>{data.summary.lastSeen||'—'}</span></div>
                  </div>
                </div>

                {/* Jail breakdown */}
                {data.jailsHit.length>0 && (
                  <div style={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:8,overflow:'hidden'}}>
                    <div style={{padding:'8px 14px',borderBottom:'0.5px solid var(--border)',fontSize:11,fontWeight:600,color:'var(--text2)',textTransform:'uppercase',letterSpacing:'.04em'}}>Jail breakdown</div>
                    <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
                      <thead>
                        <tr style={{borderBottom:'0.5px solid var(--border)'}}>
                          {['Jail','Intent','Bans','Attempts'].map(h=><th key={h} style={{padding:'7px 12px',textAlign:'left',color:'var(--text3)',fontWeight:500,fontSize:11}}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {data.jailsHit.map(j=>{
                          const m = JAIL_META[j.name]
                          return (
                            <tr key={j.name} style={{borderBottom:'0.5px solid var(--border)'}}>
                              <td style={{padding:'7px 12px'}}>
                                <span style={{fontFamily:'var(--mono)',color:'var(--blue)',fontSize:11}}>{j.name}</span>
                                {m && <span style={{marginLeft:7,fontSize:9,fontWeight:700,color:m.color,fontFamily:'var(--mono)'}}>{m.severity}</span>}
                              </td>
                              <td style={{padding:'7px 12px',color:'var(--text2)',fontSize:11}}>{m?.intent||'—'}</td>
                              <td style={{padding:'7px 12px',fontFamily:'var(--mono)',color:j.bans>0?'var(--accent2)':'var(--text2)'}}>{j.bans}</td>
                              <td style={{padding:'7px 12px',fontFamily:'var(--mono)',color:'var(--amber)'}}>{j.attempts}</td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Tried usernames */}
                {data.summary.triedUsernames.length>0 && (
                  <div style={{background:'rgba(226,75,74,0.06)',border:'0.5px solid rgba(226,75,74,0.22)',borderRadius:8,padding:'10px 14px'}}>
                    <div style={{fontSize:11,fontWeight:600,color:'var(--accent2)',marginBottom:8}}>[!] Usernames attempted ({data.summary.triedUsernames.length})</div>
                    <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
                      {data.summary.triedUsernames.map(u=><span key={u} style={{fontFamily:'var(--mono)',fontSize:11,padding:'2px 8px',background:'rgba(226,75,74,0.12)',borderRadius:4,color:'var(--accent2)'}}>{u}</span>)}
                    </div>
                  </div>
                )}

                {/* Tried ports */}
                {data.summary.triedPorts.length>0 && (
                  <div style={{background:'rgba(246,173,85,0.06)',border:'0.5px solid rgba(246,173,85,0.22)',borderRadius:8,padding:'10px 14px'}}>
                    <div style={{fontSize:11,fontWeight:600,color:'var(--amber)',marginBottom:8}}>Source ports used</div>
                    <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
                      {data.summary.triedPorts.map(p=><span key={p} style={{fontFamily:'var(--mono)',fontSize:11,padding:'2px 8px',background:'rgba(246,173,85,0.12)',borderRadius:4,color:'var(--amber)'}}>:{p}</span>)}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TIMELINE */}
            {tab==='timeline' && (
              <div>
                {data.timeline.length===0
                  ? <div style={{padding:32,textAlign:'center',color:'var(--text3)',fontSize:12}}>No timeline events found in logs for this IP</div>
                  : data.timeline.map((e,i)=>(
                    <div key={i} style={{display:'flex',gap:10,padding:'7px 2px',borderBottom:'0.5px solid var(--border)',alignItems:'flex-start'}}>
                      <span style={{fontSize:13,flexShrink:0,marginTop:1}}>{typeIcon(e.type)}</span>
                      <span style={{fontFamily:'var(--mono)',fontSize:10,color:'var(--text3)',flexShrink:0,minWidth:135,paddingTop:2}}>{e.timestamp||'—'}</span>
                      <span style={{fontSize:10,color:'var(--text3)',flexShrink:0,minWidth:70,paddingTop:2}}>{e.source}</span>
                      <span style={{fontSize:11,color:typeColor(e.type),lineHeight:1.55,wordBreak:'break-all'}}>{e.detail}</span>
                    </div>
                  ))
                }
              </div>
            )}

            {/* GEO & INTEL */}
            {tab==='geo' && (
              <div style={{display:'flex',flexDirection:'column',gap:12}}>
                {!geo ? (
                  <div style={{padding:16,background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:8,fontSize:12,color:'var(--text2)'}}>
                    Geo lookup unavailable — check internet connection.<br/>
                    <span style={{color:'var(--text3)',fontSize:11}}>Uses ip-api.com (free, no API key needed)</span>
                  </div>
                ) : (<>
                  <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
                    {[
                      {label:'Proxy / VPN',  active:geo.proxy,   color:'var(--accent2)'},
                      {label:'Hosting / DC', active:geo.hosting, color:'var(--amber)'},
                      {label:'Mobile',       active:geo.mobile,  color:'var(--blue)'},
                    ].map(f=>(
                      <span key={f.label} style={{padding:'5px 14px',borderRadius:20,fontSize:11,fontWeight:600,background:f.active?`${f.color}22`:'var(--bg3)',border:`0.5px solid ${f.active?f.color:'var(--border)'}`,color:f.active?f.color:'var(--text3)'}}>
                        {f.active?'[!] ':'[✓] '}{f.label}
                      </span>
                    ))}
                  </div>
                  <div style={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:8,overflow:'hidden'}}>
                    {[['IP',geo.query],['Country',`${geo.countryCode}  ${geo.country}`],['Region',geo.regionName],['City',geo.city],['ISP',geo.isp],['Org',geo.org],['AS',geo.as]].map(([k,v])=>(
                      <div key={k} style={{display:'flex',borderBottom:'0.5px solid var(--border)'}}>
                        <div style={{width:80,padding:'8px 14px',color:'var(--text3)',fontSize:11,fontWeight:500,flexShrink:0}}>{k}</div>
                        <div style={{padding:'8px 14px',fontFamily:'var(--mono)',fontSize:11,color:'var(--text)'}}>{v||'—'}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{fontSize:10,color:'var(--text3)'}}>Geo data via ip-api.com. For deeper intel consider AbuseIPDB or Shodan.</div>
                </>)}
              </div>
            )}
          </>)}
        </div>
      </div>
    </>
  )
}

// ─── Dashboard ────────────────────────────────────────────────────────────
function Dashboard({ jails, daemonOk, loading, error, onRefresh, onInspect }) {
  const totalBanned  = jails.reduce((s,j)=>s+j.currentlyBanned,0)
  const totalSession = jails.reduce((s,j)=>s+j.totalBanned,0)
  return (
    <div className="fade-in" style={{display:'flex',flexDirection:'column',gap:14}}>
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10}}>
        {[
          {label:'Active bans',   value:loading?'…':totalBanned,       color:totalBanned>0?'var(--accent2)':'var(--green)'},
          {label:'Session total', value:loading?'…':totalSession,      color:'var(--text)'},
          {label:'Jails online',  value:loading?'…':`${jails.length}`, color:'var(--green)'},
          {label:'Daemon',        value:daemonOk===null?'…':daemonOk?'running':'offline', color:daemonOk?'var(--green)':'var(--accent2)'},
        ].map(m=>(
          <div key={m.label} style={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:'var(--radius-lg)',padding:'14px 16px'}}>
            <div style={{fontSize:11,color:'var(--text2)',marginBottom:6,textTransform:'uppercase',letterSpacing:'.06em'}}>{m.label}</div>
            <div style={{fontSize:26,fontWeight:700,color:m.color,fontFamily:'var(--mono)'}}>{m.value}</div>
          </div>
        ))}
      </div>

      {error && <ErrorBox message={error} onRetry={onRefresh}/>}

      <Card>
        <SectionHeader icon={Lock} title="Active jails" right={<button onClick={onRefresh} style={{background:'none',border:'none',cursor:'pointer',color:'var(--text2)'}}><RefreshCw size={13}/></button>}/>
        {loading ? <LoadingBox rows={3}/> : (
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
            <thead>
              <tr style={{borderBottom:'0.5px solid var(--border)'}}>
                {['Jail','Currently banned','Session total','Banned IPs'].map(h=>(
                  <th key={h} style={{padding:'7px 14px',textAlign:'left',color:'var(--text3)',fontWeight:500,fontSize:11}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {jails.length===0 ? (
                <tr><td colSpan={4} style={{padding:'20px 14px',color:'var(--text3)',textAlign:'center',fontSize:12}}>No jails found — is fail2ban running?</td></tr>
              ) : jails.map(j=>{
                const m = JAIL_META[j.name]
                return (
                  <tr key={j.name} style={{borderBottom:'0.5px solid var(--border)'}}>
                    <td style={{padding:'8px 14px'}}>
                      <span style={{fontFamily:'var(--mono)',color:'var(--blue)',fontSize:11}}>{j.name}</span>
                      {m && <span style={{marginLeft:7,fontSize:9,fontWeight:700,color:m.color,fontFamily:'var(--mono)'}}>{m.severity}</span>}
                    </td>
                    <td style={{padding:'8px 14px',fontFamily:'var(--mono)',fontWeight:600,color:j.currentlyBanned>0?'var(--accent2)':'var(--text2)'}}>{j.currentlyBanned}</td>
                    <td style={{padding:'8px 14px',fontFamily:'var(--mono)',color:'var(--text2)'}}>{j.totalBanned}</td>
                    <td style={{padding:'8px 14px',fontSize:11,color:'var(--text2)',maxWidth:240,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                      {j.bannedIPs.length===0
                        ? <span style={{color:'var(--text3)'}}>—</span>
                        : j.bannedIPs.slice(0,3).map((ip,i)=>(
                          <span key={ip}>{i>0 && <span style={{color:'var(--text3)'}}>, </span>}<ClickableIP ip={ip} onInspect={onInspect}/></span>
                        ))}
                      {j.bannedIPs.length>3 && <span style={{color:'var(--text3)'}}> +{j.bannedIPs.length-3}</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}

// ─── Log Viewer ───────────────────────────────────────────────────────────
function LogViewer({ onInspect }) {
  const [logs,    setLogs]    = useState([])
  const [filter,  setFilter]  = useState('')
  const [level,   setLevel]   = useState('')
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  const fetchLogs = useCallback(async () => {
    setLoading(true); setError(null)
    try { const d = await api.logs(filter,level); setLogs(d.logs||[]) }
    catch(e) { setError(e.message); setLogs([]) }
    finally { setLoading(false) }
  }, [filter,level])

  useEffect(()=>{ const t=setTimeout(fetchLogs,300); return ()=>clearTimeout(t) },[fetchLogs])

  const levelColor = l => ['WARNING','ERROR','CRITICAL'].includes(l)?'var(--accent2)':l==='NOTICE'?'var(--green)':'var(--text2)'

  // Extract IP from a log message and make it clickable
  const renderMessage = (msg) => {
    const ipRe = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g
    const parts = []; let last = 0; let m
    while ((m = ipRe.exec(msg)) !== null) {
      if (m.index > last) parts.push(<span key={last}>{msg.slice(last,m.index)}</span>)
      parts.push(<ClickableIP key={m.index} ip={m[1]} onInspect={onInspect}/>)
      last = m.index + m[1].length
    }
    if (last < msg.length) parts.push(<span key={last}>{msg.slice(last)}</span>)
    return parts.length ? parts : msg
  }

  return (
    <div className="fade-in">
      <Card>
        <SectionHeader icon={Terminal} title="Log viewer — fail2ban.log" right={<button onClick={fetchLogs} style={{background:'none',border:'none',cursor:'pointer',color:'var(--text2)'}}><RefreshCw size={13}/></button>}/>
        <div style={{display:'flex',gap:8,padding:'10px 14px',borderBottom:'0.5px solid var(--border)'}}>
          <div style={{position:'relative',flex:1}}>
            <Search size={12} style={{position:'absolute',left:9,top:'50%',transform:'translateY(-50%)',color:'var(--text3)'}}/>
            <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter by IP, jail, message…"
              style={{width:'100%',paddingLeft:28,paddingRight:8,paddingTop:5,paddingBottom:5,background:'var(--bg3)',border:'0.5px solid var(--border2)',borderRadius:'var(--radius)',color:'var(--text)',fontSize:12,fontFamily:'var(--mono)',outline:'none'}}/>
          </div>
          <select value={level} onChange={e=>setLevel(e.target.value)} style={{padding:'5px 10px',background:'var(--bg3)',border:'0.5px solid var(--border2)',borderRadius:'var(--radius)',color:'var(--text)',fontSize:12,outline:'none',cursor:'pointer'}}>
            <option value="">All levels</option>
            <option value="BAN">BAN</option>
            <option value="UNBAN">UNBAN</option>
            <option value="WARNING">WARNING</option>
          </select>
        </div>
        <div style={{maxHeight:460,overflowY:'auto'}}>
          {loading ? <LoadingBox rows={6}/> : error ? <ErrorBox message={error} onRetry={fetchLogs}/> :
           logs.length===0 ? <div style={{padding:24,textAlign:'center',color:'var(--text3)',fontSize:12}}>No entries match your filters</div>
           : logs.map((l,i)=>(
            <div key={i} style={{display:'flex',gap:12,padding:'6px 14px',borderBottom:'0.5px solid var(--border)',fontSize:11,fontFamily:'var(--mono)',flexWrap:'wrap'}}>
              <span style={{color:'var(--text3)',flexShrink:0,minWidth:140}}>{l.timestamp||'—'}</span>
              <span style={{color:levelColor(l.level),flexShrink:0,minWidth:72}}>{l.level}</span>
              <span style={{color:'var(--text)',wordBreak:'break-all',lineHeight:1.6,flex:1}}>{renderMessage(l.message)}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

// ─── Reports ──────────────────────────────────────────────────────────────
function Reports({ onInspect }) {
  const [data,loading,error,fetch] = useFetch(api.reports)
  useEffect(()=>{ fetch() },[])

  if (loading) return <div className="fade-in"><Card><LoadingBox rows={5}/></Card></div>
  if (error)   return <div className="fade-in"><Card><ErrorBox message={error} onRetry={fetch}/></Card></div>

  const totalBans = data.dailyBans.reduce((s,d)=>s+d.bans,0)

  return (
    <div className="fade-in" style={{display:'flex',flexDirection:'column',gap:14}}>
      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10}}>
        {[
          {label:'Total bans (7 days)',  value:totalBans,              color:'var(--accent2)'},
          {label:'Most active jail',     value:data.byJail[0]?.name||'—',  color:'var(--blue)'},
          {label:'Jail session total',   value:data.byJail[0]?.bans||0,    color:'var(--amber)'},
        ].map(m=>(
          <div key={m.label} style={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:'var(--radius-lg)',padding:'14px 16px'}}>
            <div style={{fontSize:11,color:'var(--text2)',marginBottom:6,textTransform:'uppercase',letterSpacing:'.06em'}}>{m.label}</div>
            <div style={{fontSize:20,fontWeight:700,color:m.color,fontFamily:'var(--mono)'}}>{m.value}</div>
          </div>
        ))}
      </div>

      <Card>
        <SectionHeader icon={BarChart2} title="Bans — last 7 days" right={<Badge color="green">real data</Badge>}/>
        <div style={{padding:'16px 8px 8px'}}>
          {data.dailyBans.every(d=>d.bans===0)
            ? <div style={{padding:24,textAlign:'center',color:'var(--text3)',fontSize:12}}>No ban events in the last 7 days</div>
            : <ResponsiveContainer width="100%" height={180}>
                <BarChart data={data.dailyBans} margin={{top:0,right:8,left:-20,bottom:0}}>
                  <XAxis dataKey="day" tick={{fill:'#4a5568',fontSize:10}} axisLine={false} tickLine={false}/>
                  <YAxis tick={{fill:'#4a5568',fontSize:10}} axisLine={false} tickLine={false} allowDecimals={false}/>
                  <Tooltip contentStyle={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:6,fontSize:11}} cursor={{fill:'rgba(255,255,255,.04)'}} formatter={v=>[v,'Bans']} labelFormatter={(_,p)=>p?.[0]?.payload?.date||''}/>
                  <Bar dataKey="bans" fill="#e24b4a" radius={[3,3,0,0]}/>
                </BarChart>
              </ResponsiveContainer>
          }
        </div>
      </Card>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <Card>
          <SectionHeader icon={Lock} title="Bans by jail"/>
          <div style={{padding:'16px 8px 8px'}}>
            {data.byJail.length===0
              ? <div style={{padding:16,textAlign:'center',color:'var(--text3)',fontSize:12}}>No data</div>
              : <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={data.byJail} dataKey="bans" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={2}>
                      {data.byJail.map((_,i)=><Cell key={i} fill={PIE_COLORS[i%PIE_COLORS.length]}/>)}
                    </Pie>
                    <Legend wrapperStyle={{fontSize:11}}/>
                    <Tooltip contentStyle={{background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:6,fontSize:11}}/>
                  </PieChart>
                </ResponsiveContainer>
            }
          </div>
        </Card>

        <Card>
          <SectionHeader icon={AlertTriangle} title="Recent ban events"/>
          <div style={{maxHeight:230,overflowY:'auto'}}>
            {data.recentBans.length===0
              ? <div style={{padding:16,textAlign:'center',color:'var(--text3)',fontSize:12}}>No recent bans</div>
              : data.recentBans.slice(0,20).map((b,i)=>(
                <div key={i} style={{display:'flex',alignItems:'center',gap:10,padding:'6px 14px',borderBottom:'0.5px solid var(--border)',fontSize:11}}>
                  <ClickableIP ip={b.ip} onInspect={onInspect}/>
                  <Badge color="blue">{b.jail}</Badge>
                  <span style={{color:'var(--text3)',marginLeft:'auto'}}>{b.date}</span>
                </div>
              ))
            }
          </div>
        </Card>
      </div>
    </div>
  )
}

// ─── Banned IPs ───────────────────────────────────────────────────────────
function BannedIPs({ jails, onUnban, onInspect }) {
  const [searchQ,    setSearchQ]    = useState('')
  const [jailFilter, setJailFilter] = useState('')
  const [unbanning,  setUnbanning]  = useState(null)

  const allBans = jails.flatMap(j=>j.bannedIPs.map(ip=>({ip,jail:j.name})))
  const filtered = allBans.filter(b=>{
    const mQ = !searchQ    || b.ip.includes(searchQ)||b.jail.includes(searchQ)
    const mJ = !jailFilter || b.jail===jailFilter
    return mQ && mJ
  })

  const handleUnban = async (jail,ip) => {
    if (!window.confirm(`Unban ${ip} from ${jail}?`)) return
    setUnbanning(ip)
    try { await api.unbanIP(jail,ip); onUnban() }
    catch(e) { alert(`Unban failed: ${e.message}`) }
    finally { setUnbanning(null) }
  }

  return (
    <div className="fade-in">
      <Card>
        <SectionHeader icon={ShieldOff} title="Currently banned IPs" right={<Badge color="red">{allBans.length} active</Badge>}/>
        <div style={{display:'flex',gap:8,padding:'10px 14px',borderBottom:'0.5px solid var(--border)'}}>
          <div style={{position:'relative',flex:1}}>
            <Search size={12} style={{position:'absolute',left:9,top:'50%',transform:'translateY(-50%)',color:'var(--text3)'}}/>
            <input value={searchQ} onChange={e=>setSearchQ(e.target.value)} placeholder="Search by IP or jail…"
              style={{width:'100%',paddingLeft:28,paddingRight:8,paddingTop:5,paddingBottom:5,background:'var(--bg3)',border:'0.5px solid var(--border2)',borderRadius:'var(--radius)',color:'var(--text)',fontSize:12,fontFamily:'var(--mono)',outline:'none'}}/>
          </div>
          <select value={jailFilter} onChange={e=>setJailFilter(e.target.value)} style={{padding:'5px 10px',background:'var(--bg3)',border:'0.5px solid var(--border2)',borderRadius:'var(--radius)',color:'var(--text)',fontSize:12,outline:'none',cursor:'pointer'}}>
            <option value="">All jails</option>
            {jails.map(j=><option key={j.name} value={j.name}>{j.name}</option>)}
          </select>
        </div>
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead>
            <tr style={{borderBottom:'0.5px solid var(--border)'}}>
              {['IP address','Jail','Severity','Actions'].map(h=>(
                <th key={h} style={{padding:'7px 14px',textAlign:'left',color:'var(--text3)',fontWeight:500,fontSize:11}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length===0
              ? <tr><td colSpan={4} style={{padding:'20px 14px',textAlign:'center',color:'var(--text3)',fontSize:12}}>{allBans.length===0?'No IPs currently banned':'No results match your search'}</td></tr>
              : filtered.map((b,i)=>{
                const m = JAIL_META[b.jail]
                return (
                  <tr key={i} style={{borderBottom:'0.5px solid var(--border)'}}>
                    <td style={{padding:'8px 14px'}}><ClickableIP ip={b.ip} onInspect={onInspect}/></td>
                    <td style={{padding:'8px 14px'}}><Badge color="blue">{b.jail}</Badge></td>
                    <td style={{padding:'8px 14px'}}>
                      {m ? <span style={{fontSize:10,fontWeight:700,color:m.color,fontFamily:'var(--mono)'}}>{m.severity}</span> : <span style={{color:'var(--text3)'}}>—</span>}
                    </td>
                    <td style={{padding:'8px 14px',display:'flex',gap:6}}>
                      <button onClick={()=>onInspect(b.ip)} style={{display:'inline-flex',alignItems:'center',gap:4,background:'rgba(99,179,237,0.1)',border:'0.5px solid rgba(99,179,237,0.3)',color:'var(--blue)',borderRadius:'var(--radius)',padding:'3px 9px',fontSize:11,cursor:'pointer',fontFamily:'var(--mono)'}}>
                        [I] Investigate
                      </button>
                      <button onClick={()=>handleUnban(b.jail,b.ip)} disabled={unbanning===b.ip} style={{display:'inline-flex',alignItems:'center',gap:4,background:'rgba(226,75,74,.12)',border:'0.5px solid rgba(226,75,74,.3)',color:unbanning===b.ip?'var(--text3)':'var(--accent2)',borderRadius:'var(--radius)',padding:'3px 9px',fontSize:11,cursor:unbanning===b.ip?'not-allowed':'pointer',fontFamily:'var(--mono)'}}>
                        <Trash2 size={10}/>{unbanning===b.ip?'Unbanning…':'Unban'}
                      </button>
                    </td>
                  </tr>
                )
              })
            }
          </tbody>
        </table>
      </Card>
    </div>
  )
}

// ─── Settings ─────────────────────────────────────────────────────────────
function SettingsPage() {
  const [config,loading,error,fetchConfig] = useFetch(api.config)
  useEffect(()=>{ fetchConfig() },[])

  const checks = [
    {ok:true,  text:'Backend binds to 127.0.0.1 only'},
    {ok:true,  text:'Rate limiting: 100 req/min global, 20/min writes'},
    {ok:true,  text:'Helmet security headers (XSS, HSTS, CSP, no-sniff)'},
    {ok:true,  text:'CORS restricted to localhost origin only'},
    {ok:true,  text:'Strict IP/CIDR validation on all ban/unban calls'},
    {ok:true,  text:'WebSocket: origin check + API key on every upgrade'},
    {ok:true,  text:'execFile arg arrays — no shell injection possible'},
    {ok:false, text:'OIDC not configured — required for LAN/multi-user access'},
    {ok:false, text:'No TLS — use Caddy or Nginx reverse proxy for HTTPS'},
  ]

  return (
    <div className="fade-in" style={{display:'flex',flexDirection:'column',gap:14}}>
      <Card>
        <SectionHeader icon={Terminal} title="Live daemon config" right={<Badge color="blue">from fail2ban-client</Badge>}/>
        {loading ? <LoadingBox rows={3}/> : error ? <ErrorBox message={error} onRetry={fetchConfig}/> : (
          <div style={{padding:'14px 16px',display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:12}}>
            {config && Object.entries(config).map(([k,v])=>(
              <div key={k}>
                <div style={{fontSize:11,color:'var(--text2)',marginBottom:4,textTransform:'uppercase',letterSpacing:'.06em'}}>{k}</div>
                <div style={{padding:'5px 10px',background:'var(--bg3)',border:'0.5px solid var(--border)',borderRadius:'var(--radius)',color:'var(--text)',fontSize:12,fontFamily:'var(--mono)'}}>{v||'—'}</div>
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card>
        <SectionHeader icon={ShieldCheck} title="Security posture"/>
        <div style={{padding:'12px 16px',display:'flex',flexDirection:'column',gap:4}}>
          {checks.map((c,i)=>(
            <div key={i} style={{display:'flex',alignItems:'center',gap:10,padding:'7px 0',borderBottom:'0.5px solid var(--border)',fontSize:12}}>
              <span style={{color:c.ok?'var(--green)':'var(--amber)',fontSize:12,flexShrink:0,fontWeight:'bold'}}>{c.ok?'[✓]':'[!]'}</span>
              <span style={{color:c.ok?'var(--text)':'var(--amber)'}}>{c.text}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

// ─── useFetch helper ──────────────────────────────────────────────────────
function useFetch(apiFn) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const fetch = useCallback(async () => {
    setLoading(true); setError(null)
    try { setData(await apiFn()) }
    catch(e) { setError(e.message) }
    finally { setLoading(false) }
  }, [apiFn])
  return [data, loading, error, fetch]
}

// ─── App shell ────────────────────────────────────────────────────────────
const NAV = [
  {id:'dashboard', label:'Dashboard',  icon:Activity},
  {id:'logs',      label:'Logs',       icon:FileText},
  {id:'reports',   label:'Reports',    icon:BarChart2},
  {id:'bans',      label:'Banned IPs', icon:ShieldOff},
  {id:'settings',  label:'Settings',   icon:Settings},
]

export default function App() {
  const [page,        setPage]        = useState('dashboard')
  const [jails,       setJails]       = useState([])
  const [daemonOk,    setDaemonOk]    = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [wsState,     setWsState]     = useState('connecting')
  const [inspectedIP, setInspectedIP] = useState(null)   // ← modal state
  const wsRef = useRef(null)

  const fetchJails = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const [s,j] = await Promise.all([api.status(), api.jails()])
      setDaemonOk(s.ok); setJails(j.jails||[])
    } catch(e) { setError(e.message); setDaemonOk(false) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    fetchJails()
    try {
      const ws = createWebSocket(
        msg => {
          if (msg.type==='status') {
            if (msg.data.daemon!==undefined) setDaemonOk(msg.data.daemon.ok)
            if (msg.data.jails?.length)      setJails(msg.data.jails)
            setLoading(false)
          }
        },
        () => setWsState('error')
      )
      ws.onopen  = () => setWsState('connected')
      ws.onclose = () => setWsState('disconnected')
      wsRef.current = ws
    } catch {}
    return () => wsRef.current?.close()
  }, [fetchJails])

  const totalBanned = jails.reduce((s,j)=>s+j.currentlyBanned,0)
  const openModal   = useCallback(ip => setInspectedIP(ip), [])
  const closeModal  = useCallback(()  => setInspectedIP(null), [])

  return (
    <div style={{display:'flex',height:'100vh',overflow:'hidden',fontFamily:'var(--sans)'}}>

      {/* IP Modal — rendered at root so it floats above everything */}
      {inspectedIP && <IPModal ip={inspectedIP} onClose={closeModal}/>}

      {/* Sidebar */}
      <aside style={{width:210,background:'var(--bg2)',borderRight:'0.5px solid var(--border)',display:'flex',flexDirection:'column',flexShrink:0}}>
        <div style={{padding:'16px 16px 12px',borderBottom:'0.5px solid var(--border)'}}>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            <div style={{width:30,height:30,borderRadius:7,background:'var(--accent)',display:'flex',alignItems:'center',justifyContent:'center'}}>
              <ShieldCheck size={16} color="#fff"/>
            </div>
            <div>
              <div style={{fontSize:13,fontWeight:700}}>Fail2Ban</div>
              <div style={{fontSize:10,color:'var(--text3)'}}>Security Dashboard</div>
            </div>
          </div>
        </div>

        <nav style={{flex:1,padding:'10px 8px'}}>
          {NAV.map(({id,label,icon:Icon})=>(
            <button key={id} onClick={()=>setPage(id)} style={{display:'flex',alignItems:'center',gap:9,width:'100%',padding:'8px 10px',background:page===id?'rgba(226,75,74,.12)':'transparent',border:page===id?'0.5px solid rgba(226,75,74,.25)':'0.5px solid transparent',borderRadius:'var(--radius)',marginBottom:2,color:page===id?'var(--accent2)':'var(--text2)',fontSize:13,fontWeight:page===id?600:400,cursor:'pointer',fontFamily:'var(--sans)',transition:'all .15s'}}>
              <Icon size={14}/>{label}
              {id==='bans' && totalBanned>0 && (
                <span style={{marginLeft:'auto',background:'var(--accent)',color:'#fff',fontSize:9,fontFamily:'var(--mono)',padding:'1px 6px',borderRadius:20}}>{totalBanned}</span>
              )}
            </button>
          ))}
        </nav>

        <div style={{padding:'10px 14px',borderTop:'0.5px solid var(--border)',fontSize:11}}>
          <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:4}}>
            <StatusDot ok={daemonOk===true}/>
            <span style={{color:'var(--text2)'}}>{daemonOk===null?'Connecting…':daemonOk?'Daemon running':'Daemon offline'}</span>
          </div>
          <div style={{display:'flex',alignItems:'center',gap:6}}>
            {wsState==='connected'?<Wifi size={10} style={{color:'var(--green)'}}/>:<WifiOff size={10} style={{color:'var(--text3)'}}/>}
            <span style={{color:'var(--text3)'}}>ws {wsState}</span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main style={{flex:1,overflow:'auto',display:'flex',flexDirection:'column'}}>
        <div style={{padding:'11px 20px',borderBottom:'0.5px solid var(--border)',display:'flex',alignItems:'center',justifyContent:'space-between',background:'var(--bg2)',flexShrink:0}}>
          <div style={{fontSize:13,fontWeight:600}}>{NAV.find(n=>n.id===page)?.label}</div>
          <div style={{display:'flex',alignItems:'center',gap:8}}>
            {daemonOk===false && !loading && <Badge color="amber">[!] fail2ban unreachable</Badge>}
            {totalBanned>0 && <Badge color="red">{totalBanned} active bans</Badge>}
            {jails.length>0 && <Badge color="green">{jails.length} jails</Badge>}
          </div>
        </div>

        <div style={{flex:1,padding:18,overflow:'auto'}}>
          {page==='dashboard' && <Dashboard jails={jails} daemonOk={daemonOk} loading={loading} error={error} onRefresh={fetchJails} onInspect={openModal}/>}
          {page==='logs'      && <LogViewer onInspect={openModal}/>}
          {page==='reports'   && <Reports   onInspect={openModal}/>}
          {page==='bans'      && <BannedIPs jails={jails} onUnban={fetchJails} onInspect={openModal}/>}
          {page==='settings'  && <SettingsPage/>}
        </div>
      </main>
    </div>
  )
}
