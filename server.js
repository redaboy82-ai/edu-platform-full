const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const GAMES_DIR = process.env.GAMES_DIR ? path.resolve(process.env.GAMES_DIR) : path.join(ROOT, 'games');
const VIDEOS_DIR = process.env.VIDEOS_DIR ? path.resolve(process.env.VIDEOS_DIR) : path.join(ROOT, 'videos');
const VideO_MAX_BYTES = 600*1024*1024;
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(ROOT, 'public');
fs.mkdirSync(DATA_DIR, {recursive:true});
fs.mkdirSync(GAMES_DIR, {recursive:true});
fs.mkdirSync(VIDEOS_DIR, {recursive:true});

const sessions = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    const actual = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(actual,'hex'));
  } catch { return false; }
}
function uid(prefix='id') { return `${prefix}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`; }
function code(prefix='P') { return `${prefix}-${Math.random().toString(36).slice(2,7).toUpperCase()}`; }
function cleanPhone(v) { return String(v||'').replace(/[^0-9]/g,'').replace(/^00/,''); }
function normalizeTestUrl(raw) {
  const u=String(raw||'').trim();
  if(!u) return '';
  try {
    const x=new URL(u);
    if(!/^https?:$/.test(x.protocol)) return '';
    const m=x.pathname.match(/\/file\/d\/([^/]+)/);
    if(x.hostname==='drive.google.com' && m) return `https://drive.google.com/file/d/${m[1]}/preview`;
    const id=x.searchParams.get('id');
    if(x.hostname==='drive.google.com' && id) return `https://drive.google.com/file/d/${encodeURIComponent(id)}/preview`;
    return u;
  } catch { return ''; }
}
const DEFAULT_RECOVERY_PHONE = cleanPhone(process.env.ADMIN_RECOVERY_PHONE || '00201093559477');
function readDB(){
  try { return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); }
  catch {
    const adminPassword = process.env.ADMIN_PASSWORD || '135790';
    const db = {settings:{schoolName:'منصّة الدروس', autoWhatsApp:true}, classes:[], students:[], videos:[], games:[], electronicTests:[], results:[], videoProgress:[], activities:[], admin:{id:'admin',username:process.env.ADMIN_USERNAME||'redaawad',passwordHash:hashPassword(adminPassword),recoveryPhone:DEFAULT_RECOVERY_PHONE}};
    writeDB(db); return db;
  }
}
function writeDB(db){ fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2), 'utf8'); }
let db = readDB();
// Migrate the original demo credentials to the requested teacher account when still untouched.
if(db.admin && db.admin.username==='admin' && !db.admin.passwordChangedAt){ db.admin.username=process.env.ADMIN_USERNAME||'redaawad'; db.admin.passwordHash=hashPassword(process.env.ADMIN_PASSWORD||'135790'); writeDB(db); }
if(db.admin && !db.admin.recoveryPhone){ db.admin.recoveryPhone=DEFAULT_RECOVERY_PHONE; writeDB(db); }
db.electronicTests=Array.isArray(db.electronicTests)?db.electronicTests:[];
db.videoProgress=Array.isArray(db.videoProgress)?db.videoProgress:[];
db.activities=Array.isArray(db.activities)?db.activities:[];

function json(res,status,obj){
  const body = JSON.stringify(obj);
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Content-Length':Buffer.byteLength(body)});
  res.end(body);
}
function text(res,status,body,type='text/plain; charset=utf-8'){
  res.writeHead(status, {'Content-Type':type,'Cache-Control':'no-store','Content-Length':Buffer.byteLength(body)}); res.end(body);
}
async function body(req){
  return await new Promise((resolve,reject)=>{
    let data=''; req.on('data',c=>{ if(data.length<15*1024*1024) data+=c; }); req.on('end',()=>resolve(data)); req.on('error',reject);
  });
}
function auth(req){
  const token = (req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  const session = token && sessions.get(token);
  if(!session) return null;
  if(session.expires < Date.now()){sessions.delete(token); return null;}
  session.expires = Date.now()+8*60*60*1000;
  return session;
}
function requireRole(req,res,roles){
  const a=auth(req); if(!a || !roles.includes(a.role)){json(res,401,{error:'غير مصرح'});return null;} return a;
}
function studentPublic(st, teacher=false){const base={id:st.id,name:st.name,username:st.username,classId:st.classId,phone:st.phone||'',parentName:st.parentName||'',parentPhone:st.parentPhone||'',parentCode:st.parentCode,permissions:st.permissions||{video:true,game:true}};if(teacher){base.initialPassword=st.initialPassword||'';base.initialParentPassword=st.initialParentPassword||'';}return base;}
function classPublic(c){return {...c};}
function gamePublic(g){return {id:g.id,title:g.title,classId:g.classId,description:g.description||'',filename:g.filename||''};}
function resultPublic(r){return {...r};}
function videoPublic(v){return {id:v.id,title:v.title,classId:v.classId,description:v.description||'',durationSeconds:Number(v.durationSeconds||0),sourceType:v.sourceType||'url',url:v.sourceType==='upload'?null:(v.url||'')};}
function testPublic(t){return {id:t.id,title:t.title,classId:t.classId,description:t.description||'',url:t.url};}
function activityPublic(a){return {...a};}
function progressFor(studentId,videoId){return (db.videoProgress||[]).find(x=>x.studentId===studentId&&x.videoId===videoId)||null;}
function activitiesFor(studentId){return (db.activities||[]).filter(x=>x.studentId===studentId&&x.type!=='login'&&x.type!=='logout'&&x.type!=='page_view').sort((a,b)=>b.createdAt-a.createdAt);}
function issueAccessUrl(req,id){const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');return `/video-stream/${encodeURIComponent(id)}?token=${encodeURIComponent(token)}`;}

async function handle(req,res){
  const url = new URL(req.url, `http://${req.headers.host||'localhost'}`);
  const pathname=url.pathname;
  if(req.method==='GET' && pathname==='/api/health') return json(res,200,{ok:true});
  if(req.method==='GET' && pathname==='/') return serveFile(path.join(PUBLIC_DIR,'index.html'),res);
  if(req.method==='GET' && pathname.startsWith('/assets/')) return serveFile(path.join(PUBLIC_DIR,pathname.slice(8)),res);
  if(req.method==='GET' && pathname.startsWith('/game/')){
    const id=path.basename(pathname);
    const sessionToken=url.searchParams.get('token'); const a=sessionToken?sessions.get(sessionToken):auth(req); if(!a || !['teacher','student','parent'].includes(a.role) || a.expires<Date.now()) return text(res,401,'غير مصرح');
    const g=db.games.find(x=>x.id===id); if(!g) return text(res,404,'اللعبة غير موجودة');
    const f=path.join(GAMES_DIR,g.filename); if(!fs.existsSync(f)) return text(res,404,'ملف اللعبة غير موجود');
    if(a.role==='student'){const st=db.students.find(x=>x.id===a.id); if(!st || g.classId!==st.classId || !st.permissions?.game) return text(res,403,'لا توجد صلاحية');}
    if(a.role==='parent'){const st=db.students.find(x=>x.id===a.id); if(!st || g.classId!==st.classId) return text(res,403,'غير مصرح');}
    return serveFile(f,res,'text/html; charset=utf-8',false);
  }
  if(req.method==='GET' && pathname.startsWith('/video-stream/')){
    const token=url.searchParams.get('token'); const a=token?sessions.get(token):auth(req);
    if(!a || !['teacher','student','parent'].includes(a.role) || (a.expires<Date.now())) return text(res,401,'غير مصرح');
    const id=path.basename(pathname); const v=(db.videos||[]).find(x=>x.id===id); if(!v) return text(res,404,'الفيديو غير موجود');
    if(v.sourceType!=='upload') return text(res,400,'هذا فيديو بالرابط الخارجي');
    if(a.role==='student'){const st=db.students.find(x=>x.id===a.id); if(!st||st.classId!==v.classId||!st.permissions?.video)return text(res,403,'لا توجد صلاحية');}
    if(a.role==='parent'){const st=db.students.find(x=>x.id===a.id); if(!st||st.classId!==v.classId)return text(res,403,'غير مصرح');}
    const f=path.join(VIDEOS_DIR,v.filename||''); if(!fs.existsSync(f)) return text(res,404,'ملف الفيديو غير موجود');
    return streamVideo(f,res,v.mimeType||'video/mp4',req.headers.range);
  }
  if(req.method==='POST' && pathname==='/api/login'){
    const b=JSON.parse(await body(req)||'{}'); const role=b.role; const username=String(b.username||'').trim(); const password=String(b.password||'');
    let user=null;
    if(role==='teacher'){
      if(username===db.admin.username && verifyPassword(password,db.admin.passwordHash)) user={id:db.admin.id,role:'teacher',name:'المعلم / الإدارة'};
    } else if(role==='student'){
      user=db.students.find(s=>s.username===username && verifyPassword(password,s.passwordHash)); if(user) user={id:user.id,role:'student',name:user.name};
    } else if(role==='parent'){
      user=db.students.find(s=>s.parentCode===username && verifyPassword(password,s.parentPasswordHash)); if(user) user={id:user.id,role:'parent',name:safeParentName(user)};
    }
    if(!user) return json(res,401,{error:'بيانات الدخول غير صحيحة'});
    const token=crypto.randomBytes(32).toString('hex'); sessions.set(token,{...user,expires:Date.now()+8*60*60*1000});
    return json(res,200,{token,user});
  }
  if(req.method==='POST' && pathname==='/api/logout'){
    const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); if(token)sessions.delete(token); return json(res,200,{ok:true});
  }
  if(req.method==='POST' && pathname==='/api/admin/forgot'){
    const now=Date.now();
    if(db.admin.resetCode && db.admin.resetCode.lastSentAt && now-db.admin.resetCode.lastSentAt<60*1000) return json(res,429,{error:'انتظر دقيقة قبل طلب رمز جديد'});
    if(!db.admin.recoveryPhone) return json(res,400,{error:'لا يوجد رقم استعادة مسجّل لهذا الحساب. تواصل مع من يدير الخادم.'});
    const code=String(Math.floor(100000+Math.random()*900000));
    db.admin.resetCode={hash:hashPassword(code),expires:now+15*60*1000,attempts:0,lastSentAt:now}; writeDB(db);
    const msg=`رمز استعادة الدخول لحساب المعلم في منصة الدروس: ${code}\nصالح لمدة 15 دقيقة. إذا لم تطلب هذا الرمز، تجاهل الرسالة.`;
    const out=await sendWhatsAppRaw(db.admin.recoveryPhone,msg);
    if(out.mode!=='automatic'){
      // No WhatsApp Cloud API configured: don't leave a code nobody can receive automatically.
      db.admin.resetCode=null; writeDB(db);
      return json(res,200,{ok:true,mode:'unavailable',message:'الإرسال الآلي عبر واتساب غير مفعّل على هذا الخادم (يتطلب ضبط WHATSAPP_TOKEN و WHATSAPP_PHONE_NUMBER_ID). استخدم سكربت الطوارئ reset-admin.js من جهاز الخادم لإعادة ضبط بيانات الدخول.'});
    }
    return json(res,200,{ok:true,mode:'automatic',message:'تم إرسال رمز الاستعادة عبر واتساب إلى الرقم المسجّل.'});
  }
  if(req.method==='POST' && pathname==='/api/admin/reset'){
    const b=JSON.parse(await body(req)||'{}');
    const rc=db.admin.resetCode;
    if(!rc || !rc.expires || rc.expires<Date.now()) return json(res,400,{error:'الرمز غير صالح أو منتهي، اطلب رمزًا جديدًا'});
    if(rc.attempts>=5){ db.admin.resetCode=null; writeDB(db); return json(res,400,{error:'محاولات كثيرة فاشلة، اطلب رمزًا جديدًا'}); }
    if(!b.code || !verifyPassword(String(b.code).trim(),rc.hash)){ rc.attempts=(rc.attempts||0)+1; writeDB(db); return json(res,400,{error:'الرمز غير صحيح'}); }
    const newPassword=String(b.password||''); if(!newPassword||newPassword.length<6) return json(res,400,{error:'كلمة المرور يجب أن تكون 6 أحرف على الأقل'});
    let newUsername=String(b.username||'').trim()||db.admin.username;
    if(newUsername.length<3||/\s/.test(newUsername)) return json(res,400,{error:'اسم المستخدم يجب أن يكون 3 أحرف على الأقل وبدون مسافات'});
    db.admin.username=newUsername; db.admin.passwordHash=hashPassword(newPassword); db.admin.passwordChangedAt=Date.now(); db.admin.usernameChangedAt=Date.now(); db.admin.resetCode=null;
    writeDB(db);
    return json(res,200,{ok:true,username:newUsername});
  }
  if(req.method==='GET' && pathname==='/api/me'){
    const a=auth(req); if(!a)return json(res,401,{error:'انتهت الجلسة'}); return json(res,200,{user:a});
  }
  if(req.method==='POST' && pathname==='/api/admin/password'){if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.password||String(b.password).length<6)return json(res,400,{error:'كلمة المرور يجب أن تكون 6 أحرف على الأقل'});if(!b.currentPassword||!verifyPassword(b.currentPassword,db.admin.passwordHash))return json(res,400,{error:'كلمة المرور الحالية غير صحيحة'});db.admin.passwordHash=hashPassword(b.password);db.admin.passwordChangedAt=Date.now();writeDB(db);return json(res,200,{ok:true});}
  if(req.method==='POST' && pathname==='/api/admin/username'){
    if(!requireRole(req,res,['teacher']))return;
    const b=JSON.parse(await body(req)||'{}');
    const newUsername=String(b.username||'').trim();
    if(!newUsername||newUsername.length<3) return json(res,400,{error:'اسم المستخدم يجب أن يكون 3 أحرف على الأقل'});
    if(/\s/.test(newUsername)) return json(res,400,{error:'اسم المستخدم يجب ألا يحتوي على مسافات'});
    if(!b.currentPassword||!verifyPassword(b.currentPassword,db.admin.passwordHash)) return json(res,400,{error:'كلمة المرور الحالية غير صحيحة'});
    db.admin.username=newUsername; db.admin.usernameChangedAt=Date.now(); writeDB(db);
    return json(res,200,{ok:true,username:newUsername});
  }
  if(req.method==='POST' && pathname==='/api/admin/recovery-phone'){
    if(!requireRole(req,res,['teacher']))return;
    const b=JSON.parse(await body(req)||'{}');
    const phone=cleanPhone(b.phone);
    if(!phone||phone.length<8) return json(res,400,{error:'رقم الهاتف غير صحيح'});
    if(!b.currentPassword||!verifyPassword(b.currentPassword,db.admin.passwordHash)) return json(res,400,{error:'كلمة المرور الحالية غير صحيحة'});
    db.admin.recoveryPhone=phone; writeDB(db);
    return json(res,200,{ok:true,recoveryPhone:phone});
  }
  if(req.method==='GET' && pathname==='/api/teacher/dashboard'){
    if(!requireRole(req,res,['teacher']))return; return json(res,200,{settings:db.settings,adminUsername:db.admin.username,adminRecoveryPhone:db.admin.recoveryPhone||'',classes:db.classes.map(classPublic),students:db.students.map(x=>studentPublic(x,true)),videos:(db.videos||[]).map(videoPublic),games:db.games.map(gamePublic),electronicTests:db.electronicTests.map(testPublic),results:db.results.map(resultPublic).reverse(),videoProgress:db.videoProgress,activities:db.activities.filter(a=>a.type!=='login'&&a.type!=='logout'&&a.type!=='page_view')});
  }
  if(req.method==='POST' && pathname==='/api/classes'){
    if(!requireRole(req,res,['teacher']))return; const b=JSON.parse(await body(req)||'{}'); if(!b.name)return json(res,400,{error:'اسم الصف مطلوب'}); const c={id:uid('class'),name:String(b.name).trim(),subject:String(b.subject||'').trim(),createdAt:Date.now()}; db.classes.push(c);writeDB(db);return json(res,201,{class:c});
  }
  if(req.method==='PUT' && pathname.startsWith('/api/classes/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname); const c=db.classes.find(x=>x.id===id);if(!c)return json(res,404,{error:'الصف غير موجود'});const b=JSON.parse(await body(req)||'{}');Object.assign(c,{name:String(b.name||c.name).trim(),subject:String(b.subject??c.subject).trim()});writeDB(db);return json(res,200,{class:c});
  }
  if(req.method==='DELETE' && pathname.startsWith('/api/classes/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname);db.classes=db.classes.filter(x=>x.id!==id);db.students.forEach(s=>{if(s.classId===id)s.classId=''});writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='POST' && pathname==='/api/students'){
    if(!requireRole(req,res,['teacher']))return; const b=JSON.parse(await body(req)||'{}'); if(!b.name||!b.classId||!b.parentPhone)return json(res,400,{error:'أكمل اسم الطالب والصف ورقم ولي الأمر'}); if(!db.classes.some(c=>c.id===b.classId))return json(res,400,{error:'الصف غير موجود'});
    let username=String(b.username||'').trim()||`student_${Math.random().toString(36).slice(2,7)}`; while(db.students.some(s=>s.username===username))username+=Math.floor(Math.random()*9);
    let password=String(b.password||'').trim()||Math.random().toString(36).slice(2,8); const parentPassword=String(b.parentPassword||'').trim()||Math.random().toString(36).slice(2,8);
    const st={id:uid('student'),name:String(b.name).trim(),classId:b.classId,phone:cleanPhone(b.phone),parentName:String(b.parentName||'').trim(),parentPhone:cleanPhone(b.parentPhone),username,passwordHash:hashPassword(password),parentCode:code('P'),parentPasswordHash:hashPassword(parentPassword),initialPassword:password,initialParentPassword:parentPassword,permissions:{video:true,game:true},createdAt:Date.now()};db.students.push(st);writeDB(db);return json(res,201,{student:studentPublic(st),credentials:{username,password,parentCode:st.parentCode,parentPassword}});
  }
  if(req.method==='PUT' && pathname.startsWith('/api/students/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname);const st=db.students.find(x=>x.id===id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const b=JSON.parse(await body(req)||'{}');Object.assign(st,{name:String(b.name??st.name).trim(),classId:b.classId??st.classId,phone:cleanPhone(b.phone??st.phone),parentName:String(b.parentName??st.parentName).trim(),parentPhone:cleanPhone(b.parentPhone??st.parentPhone)});if(b.password){st.passwordHash=hashPassword(b.password);st.initialPassword=b.password;}if(b.parentPassword){st.parentPasswordHash=hashPassword(b.parentPassword);st.initialParentPassword=b.parentPassword;}writeDB(db);return json(res,200,{student:studentPublic(st)});
  }
  if(req.method==='DELETE' && pathname.startsWith('/api/students/')){
    if(!requireRole(req,res,['teacher']))return; const id=path.basename(pathname);db.students=db.students.filter(x=>x.id!==id);db.results=db.results.filter(x=>x.studentId!==id);writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='PATCH' && pathname.match(/^\/api\/students\/[^/]+\/permissions$/)){
    if(!requireRole(req,res,['teacher']))return; const id=pathname.split('/')[3];const st=db.students.find(x=>x.id===id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const b=JSON.parse(await body(req)||'{}');st.permissions={...st.permissions,...b};writeDB(db);return json(res,200,{student:studentPublic(st)});
  }
  if(req.method==='POST' && pathname==='/api/videos'){if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.title||!b.classId||!b.url)return json(res,400,{error:'أكمل عنوان الفيديو والرابط والصف'});const v={id:uid('video'),title:String(b.title).trim(),url:String(b.url).trim(),classId:b.classId,description:String(b.description||'').trim(),durationSeconds:Number(b.durationSeconds||0),sourceType:'url',createdAt:Date.now()};db.videos=db.videos||[];db.videos.push(v);writeDB(db);return json(res,201,{video:videoPublic(v)});}
  if(req.method==='POST' && pathname==='/api/videos/upload') {
    if(!requireRole(req,res,['teacher']))return;
    try{
      const result=await parseMultipartUpload(req,res,VideO_MAX_BYTES);
      if(!result.file) return json(res,400,{error:'اختر ملف الفيديو'});
      if(!result.fields.title||!result.fields.classId){try{fs.unlinkSync(result.file.path)}catch{};return json(res,400,{error:'أكمل عنوان الفيديو والصف والملف'});}
      const existingId=String(result.fields.existingId||'').trim(); const id=existingId||uid('video'); const ext=(path.extname(result.file.originalName)||'.mp4').toLowerCase(); const finalName=id+ext; const final=path.join(VIDEOS_DIR,finalName);
      const old=existingId?db.videos.find(x=>x.id===existingId):null; if(existingId&&!old){try{fs.unlinkSync(result.file.path)}catch{};return json(res,404,{error:'الفيديو المطلوب استبداله غير موجود'});}
      try{if(old?.filename&&old.filename!==finalName){try{fs.unlinkSync(path.join(VIDEOS_DIR,old.filename))}catch{}} fs.renameSync(result.file.path,final);}catch(e){console.error('video upload rename failed:',e);try{fs.unlinkSync(result.file.path)}catch{};return json(res,500,{error:'تعذر حفظ الفيديو'});}
      const v=old||{id};Object.assign(v,{id,title:String(result.fields.title).trim(),classId:String(result.fields.classId),description:String(result.fields.description||'').trim(),durationSeconds:Number(result.fields.durationSeconds||0),sourceType:'upload',filename:finalName,mimeType:result.file.mimeType||'video/mp4',originalName:result.file.originalName,sizeBytes:result.file.size,createdAt:old?.createdAt||Date.now()});
      if(!old)db.videos.push(v); else db.videoProgress.filter(x=>x.videoId===id).forEach(x=>{x.durationSeconds=v.durationSeconds}); writeDB(db);return json(res,old?200:201,{video:videoPublic(v)});
    }catch(e){console.error(e);return json(res,400,{error:e.message||'تعذر رفع الفيديو'});}
  }
  if(req.method==='PUT' && pathname.startsWith('/api/videos/')){if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);db.videos=db.videos||[];const v=db.videos.find(x=>x.id===id);if(!v)return json(res,404,{error:'الفيديو غير موجود'});const b=JSON.parse(await body(req)||'{}');Object.assign(v,{title:String(b.title||v.title).trim(),url:b.sourceType==='url'?String(b.url||v.url).trim():v.url,classId:b.classId||v.classId,description:String(b.description??v.description).trim(),durationSeconds:Number(b.durationSeconds ?? v.durationSeconds ?? 0),sourceType:b.sourceType||v.sourceType});writeDB(db);return json(res,200,{video:videoPublic(v)});}
  if(req.method==='DELETE' && pathname.startsWith('/api/videos/')){if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);const old=db.videos.find(x=>x.id===id);if(old?.filename){try{fs.unlinkSync(path.join(VIDEOS_DIR,old.filename))}catch{}}db.videos=(db.videos||[]).filter(x=>x.id!==id);db.videoProgress=db.videoProgress.filter(x=>x.videoId!==id);db.activities=db.activities.filter(x=>x.videoId!==id);writeDB(db);return json(res,200,{ok:true});}
  if(req.method==='POST' && pathname==='/api/video-progress'){
    const a=requireRole(req,res,['student']);if(!a)return; const b=JSON.parse(await body(req)||'{}'); const v=db.videos.find(x=>x.id===b.videoId); const st=db.students.find(x=>x.id===a.id); if(!v||!st||v.classId!==st.classId||!st.permissions?.video)return json(res,403,{error:'لا توجد صلاحية'});
    const duration=Math.max(0,Number(b.durationSeconds||v.durationSeconds||0)); const watched=Math.max(0,Number(b.watchedSeconds||0)); const position=Math.max(0,Number(b.positionSeconds||0)); let p=db.videoProgress.find(x=>x.studentId===st.id&&x.videoId===v.id); const now=Date.now(); if(!p){p={id:uid('vp'),studentId:st.id,videoId:v.id,durationSeconds:duration,watchedSeconds:watched,lastPositionSeconds:position,openCount:1,completed:false,lastWatchedAt:now,createdAt:now};db.videoProgress.push(p);}else{p.durationSeconds=duration||p.durationSeconds;p.watchedSeconds=Math.max(p.watchedSeconds,watched);p.lastPositionSeconds=position;p.openCount=Math.max(1,p.openCount||1);p.lastWatchedAt=now;p.completed=!!p.completed || (p.durationSeconds>0 && p.watchedSeconds/p.durationSeconds>=0.95);}
    const ev=String(b.event||'progress'); if(['open','play','pause','progress','ended'].includes(ev) && (ev!=='progress'||!db.activities.some(x=>x.studentId===st.id&&x.videoId===v.id&&x.type==='video_progress'&&now-x.createdAt<8000))){db.activities.push({id:uid('act'),studentId:st.id,type:ev==='ended'?'video_completed':ev==='open'?'video_open':'video_progress',videoId:v.id,title:v.title,watchedSeconds:p.watchedSeconds,positionSeconds:p.lastPositionSeconds,durationSeconds:p.durationSeconds,createdAt:now});}
    writeDB(db); return json(res,200,{progress:p});
  }
  if(req.method==='POST' && pathname==='/api/games'){
    if(!requireRole(req,res,['teacher']))return; const b=JSON.parse(await body(req)||'{}'); if(!b.title||!b.classId||!b.html)return json(res,400,{error:'اسم اللعبة والصف وملف HTML مطلوبة'});if(Buffer.byteLength(b.html,'utf8')>12*1024*1024)return json(res,400,{error:'حجم اللعبة أكبر من 12MB'});
    const id=uid('game'),filename=id+'.html';fs.writeFileSync(path.join(GAMES_DIR,filename),String(b.html),'utf8');const g={id,title:String(b.title).trim(),classId:b.classId,description:String(b.description||'').trim(),filename,createdAt:Date.now()};db.games.push(g);writeDB(db);return json(res,201,{game:gamePublic(g)});
  }
  if(req.method==='PUT' && pathname.startsWith('/api/games/')){
    if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);const g=db.games.find(x=>x.id===id);if(!g)return json(res,404,{error:'اللعبة غير موجودة'});const b=JSON.parse(await body(req)||'{}');Object.assign(g,{title:String(b.title??g.title).trim(),classId:b.classId??g.classId,description:String(b.description??g.description).trim()});if(b.html){if(Buffer.byteLength(b.html,'utf8')>12*1024*1024)return json(res,400,{error:'حجم اللعبة أكبر من 12MB'});fs.writeFileSync(path.join(GAMES_DIR,g.filename),String(b.html),'utf8');}writeDB(db);return json(res,200,{game:gamePublic(g)});
  }
  if(req.method==='DELETE' && pathname.startsWith('/api/games/')){
    if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);const g=db.games.find(x=>x.id===id);if(g){try{fs.unlinkSync(path.join(GAMES_DIR,g.filename))}catch{}}db.games=db.games.filter(x=>x.id!==id);writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='POST' && pathname==='/api/electronic-tests'){if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.title||!b.url||!b.classId)return json(res,400,{error:'أكمل عنوان الاختبار والرابط والصف'});const normalizedTestUrl=normalizeTestUrl(b.url);if(!normalizedTestUrl)return json(res,400,{error:'رابط الاختبار غير صالح'});const t={id:uid('test'),title:String(b.title).trim(),url:normalizedTestUrl,classId:b.classId,description:String(b.description||'').trim(),createdAt:Date.now()};db.electronicTests.push(t);writeDB(db);return json(res,201,{test:testPublic(t)});}
  if(req.method==='PUT' && pathname.startsWith('/api/electronic-tests/')){if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);const t=db.electronicTests.find(x=>x.id===id);if(!t)return json(res,404,{error:'الاختبار غير موجود'});const b=JSON.parse(await body(req)||'{}');const nextUrl=normalizeTestUrl(b.url||t.url);if(!nextUrl)return json(res,400,{error:'رابط الاختبار غير صالح'});Object.assign(t,{title:String(b.title||t.title).trim(),url:nextUrl,classId:b.classId||t.classId,description:String(b.description??t.description).trim()});writeDB(db);return json(res,200,{test:testPublic(t)});}
  if(req.method==='DELETE' && pathname.startsWith('/api/electronic-tests/')){if(!requireRole(req,res,['teacher']))return;const id=path.basename(pathname);db.electronicTests=db.electronicTests.filter(x=>x.id!==id);writeDB(db);return json(res,200,{ok:true});}
  if(req.method==='POST' && pathname==='/api/activity'){const a=requireRole(req,res,['student']);if(!a)return;const b=JSON.parse(await body(req)||'{}');const st=db.students.find(x=>x.id===a.id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const allowed=['game_open','test_open'];if(!allowed.includes(b.type))return json(res,400,{error:'نشاط غير صالح'});const item={id:uid('act'),studentId:a.id,type:b.type,gameId:b.gameId||null,testId:b.testId||null,title:String(b.title||''),createdAt:Date.now()};db.activities.push(item);writeDB(db);return json(res,201,{activity:item});}

  if(req.method==='GET' && pathname==='/api/student/me'){
    const a=requireRole(req,res,['student']);if(!a)return;const st=db.students.find(x=>x.id===a.id);if(!st)return json(res,404,{error:'الطالب غير موجود'});const games=db.games.filter(g=>g.classId===st.classId&&st.permissions?.game);const videos=(db.videos||[]).filter(v=>v.classId===st.classId&&st.permissions?.video);const tests=db.electronicTests.filter(t=>t.classId===st.classId);const results=db.results.filter(r=>r.studentId===st.id).reverse();const vp=db.videoProgress.filter(x=>x.studentId===st.id);const acts=activitiesFor(st.id);return json(res,200,{student:studentPublic(st),class:classPublic(db.classes.find(c=>c.id===st.classId)||{name:'بدون صف'}),games:games.map(gamePublic),videos:videos.map(videoPublic),tests:tests.map(testPublic),results,videoProgress:vp,activities:acts});
  }
  if(req.method==='GET' && pathname==='/api/parent/me'){
    const a=requireRole(req,res,['parent']);if(!a)return;const st=db.students.find(x=>x.id===a.id);const games=db.games.filter(g=>g.classId===st.classId);const results=db.results.filter(r=>r.studentId===st.id).reverse();const videos=(db.videos||[]).filter(v=>v.classId===st.classId);const tests=db.electronicTests.filter(t=>t.classId===st.classId);const vp=db.videoProgress.filter(x=>x.studentId===st.id);const acts=activitiesFor(st.id);const gameIds=[...new Set(acts.filter(x=>x.type==='game_open').map(x=>x.gameId).filter(Boolean).concat(results.filter(r=>r.gameId).map(r=>r.gameId)))];const testIds=[...new Set(acts.filter(x=>x.type==='test_open').map(x=>x.testId).filter(Boolean).concat(results.filter(r=>r.testId).map(r=>r.testId)))];return json(res,200,{student:studentPublic(st),class:classPublic(db.classes.find(c=>c.id===st.classId)||{name:'بدون صف'}),games:games.filter(g=>gameIds.includes(g.id)).map(gamePublic),allGames:games.map(gamePublic),videos:videos.map(videoPublic),tests:tests.filter(t=>testIds.includes(t.id)).map(testPublic),allTests:tests.map(testPublic),results,videoProgress:vp,activities:acts});
  }
  if(req.method==='POST' && pathname==='/api/results'){
    const a=requireRole(req,res,['student','teacher']);if(!a)return;
    const b=JSON.parse(await body(req)||'{}'); const stId=a.role==='student'?a.id:b.studentId; const st=db.students.find(x=>x.id===stId);
    const isTest=!!b.testId; const item=isTest?db.electronicTests.find(x=>x.id===b.testId):db.games.find(x=>x.id===b.gameId);
    if(!st||!item)return json(res,400,{error:isTest?'الطالب أو الاختبار غير موجود':'الطالب أو اللعبة غير موجود'});
    if(item.classId!==st.classId)return json(res,403,{error:'النشاط لا ينتمي إلى صف الطالب'});
    if(!isTest && a.role==='student' && !st.permissions?.game)return json(res,403,{error:'لا توجد صلاحية لهذه اللعبة'});
    let score=Number(b.score),total=Number(b.total); if(!Number.isFinite(score)||!Number.isFinite(total)||total<=0)return json(res,400,{error:'النتيجة غير صالحة'});
    score=Math.max(0,Math.min(total,score)); const pct=Math.round(score/total*100);
    const r={id:uid('result'),studentId:st.id,studentName:st.name,resultType:isTest?'test':'game',gameId:isTest?null:item.id,testId:isTest?item.id:null,gameTitle:isTest?null:item.title,testTitle:isTest?item.title:null,title:item.title,score,total,percentage:pct,parentPhone:st.parentPhone,parentName:st.parentName,createdAt:Date.now(),notified:false};
    db.results.push(r);writeDB(db);const notify=await sendWhatsAppIfConfigured(st,r);return json(res,201,{result:r,whatsapp:notify});
  }
  if(req.method==='POST' && pathname.startsWith('/api/results/') && pathname.endsWith('/notify')){
    if(!requireRole(req,res,['teacher','parent']))return;const id=pathname.split('/')[3];const r=db.results.find(x=>x.id===id);if(!r)return json(res,404,{error:'النتيجة غير موجودة'});const st=db.students.find(x=>x.id===r.studentId);const out=await sendWhatsAppIfConfigured(st,r);return json(res,200,{whatsapp:out});
  }
  if(req.method==='GET' && pathname.startsWith('/api/teacher/students/') && pathname.endsWith('/report')){
    if(!requireRole(req,res,['teacher']))return; const parts=pathname.split('/'); const id=parts[4]; const st=db.students.find(x=>x.id===id); if(!st)return json(res,404,{error:'الطالب غير موجود'});
    const videos=(db.videos||[]).filter(v=>v.classId===st.classId); const vp=db.videoProgress.filter(x=>x.studentId===id); const studentResults=db.results.filter(r=>r.studentId===id); const entered=[...new Set(db.activities.filter(x=>x.studentId===id&&x.type==='game_open').map(x=>x.gameId).filter(Boolean))]; const enteredTests=[...new Set(db.activities.filter(x=>x.studentId===id&&x.type==='test_open').map(x=>x.testId).filter(Boolean).concat(studentResults.filter(r=>r.testId).map(r=>r.testId)))]; const games=db.games.filter(g=>entered.includes(g.id)||studentResults.some(r=>r.gameId===g.id)); const tests=db.electronicTests.filter(t=>enteredTests.includes(t.id)); const results=studentResults.sort((a,b)=>b.createdAt-a.createdAt); const activities=activitiesFor(id);
    return json(res,200,{student:studentPublic(st,true),class:classPublic(db.classes.find(c=>c.id===st.classId)||{name:'بدون صف'}),videos:videos.map(videoPublic),videoProgress:vp,games:games.map(gamePublic),tests:tests.map(testPublic),results,activities});
  }
  if(req.method==='GET' && pathname==='/api/export'){
    if(!requireRole(req,res,['teacher']))return; return json(res,200,{version:1,exportedAt:new Date().toISOString(),db:{...db,admin:{username:db.admin.username}}});
  }
  if(req.method==='POST' && pathname==='/api/import'){
    if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');if(!b.db||!Array.isArray(b.db.classes)||!Array.isArray(b.db.students))return json(res,400,{error:'ملف النسخة الاحتياطية غير صالح'});db={...db,...b.db,admin:db.admin,videos:Array.isArray(b.db.videos)?b.db.videos:(db.videos||[]),electronicTests:Array.isArray(b.db.electronicTests)?b.db.electronicTests:(db.electronicTests||[]),videoProgress:Array.isArray(b.db.videoProgress)?b.db.videoProgress:(db.videoProgress||[]),activities:Array.isArray(b.db.activities)?b.db.activities:(db.activities||[])};writeDB(db);return json(res,200,{ok:true});
  }
  if(req.method==='PATCH' && pathname==='/api/settings'){
    if(!requireRole(req,res,['teacher']))return;const b=JSON.parse(await body(req)||'{}');db.settings={...db.settings,...b};writeDB(db);return json(res,200,{settings:db.settings});
  }
  return json(res,404,{error:'المسار غير موجود'});
}
function safeParentName(st){return st.parentName||'ولي الأمر';}
async function sendWhatsAppRaw(phone,msg){
  const manual=`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  const token=process.env.WHATSAPP_TOKEN; const phoneNumberId=process.env.WHATSAPP_PHONE_NUMBER_ID; const apiVersion=process.env.WHATSAPP_API_VERSION||'v23.0';
  if(!token||!phoneNumberId||!phone){ return {mode:'manual',url:manual,message:'تم تجهيز رسالة واتساب. للإرسال الآلي ضع بيانات WhatsApp Cloud API في متغيرات البيئة.'}; }
  try{
    const url=`https://graph.facebook.com/${apiVersion}/${phoneNumberId}/messages`;
    const payload={messaging_product:'whatsapp',to:phone,type:'text',text:{body:msg}};
    const resp=await fetch(url,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await resp.json();
    if(!resp.ok) return {mode:'manual',url:manual,message:'تعذر الإرسال الآلي، استخدم الرابط الجاهز.',error:data};
    return {mode:'automatic',message:'تم الإرسال تلقائياً عبر واتساب.'};
  }catch(e){return {mode:'manual',url:manual,message:'تعذر الاتصال بخدمة واتساب، استخدم الرابط الجاهز.',error:e.message};}
}
async function sendWhatsAppIfConfigured(st,r){
  const kind=r.resultType==='test'?'الاختبار الإلكتروني':'اللعبة التعليمية'; const title=r.title||r.gameTitle||r.testTitle||'النشاط';
  const msg=`السلام عليكم،\nتم الانتهاء من ${kind} "${title}" للطالب ${r.studentName}.\nالدرجة: ${r.score} من ${r.total}\nالنسبة: ${r.percentage}%\nمع تمنياتنا بالتوفيق.`;
  const phone=cleanPhone(st?.parentPhone);
  const out=await sendWhatsAppRaw(phone,msg);
  if(out.mode==='automatic'){ r.notified=true;r.notifiedAt=Date.now();writeDB(db); }
  return out;
}
async function parseMultipartUpload(req,res,maxBytes){
  const ct=req.headers['content-type']||''; const m=ct.match(/boundary="?([^";]+)"?/i); if(!m)throw new Error('بيانات الرفع غير صالحة');
  const boundary=Buffer.from(`--${m[1]}`), marker=Buffer.from(`\r\n--${m[1]}`), crlf=Buffer.from('\r\n');
  let buf=Buffer.alloc(0), state='preamble', current=null, fields={}, file=null, total=0, ended=false;
  const temp=path.join(VIDEOS_DIR,`upload_${uid('tmp')}`);
  let ws=null, fileClosePromise=null;
  const parseHeaders=(b)=>{const out={};for(const line of b.toString('utf8').split('\r\n')){const i=line.indexOf(':');if(i<0)continue;out[line.slice(0,i).trim().toLowerCase()]=line.slice(i+1).trim()}return out};
  const disposition=(v)=>{const r={};for(const part of String(v||'').split(';').slice(1)){const i=part.indexOf('=');if(i<0)continue;let val=part.slice(i+1).trim();if(val.startsWith('"')&&val.endsWith('"'))val=val.slice(1,-1);r[part.slice(0,i).trim()]=val}return r};
  function startPart(headers){const d=disposition(headers['content-disposition']);current={name:d.name||'',filename:d.filename||null,mime:headers['content-type']||''};if(current.filename){ws=fs.createWriteStream(temp);fileClosePromise=new Promise((resolve,reject)=>{ws.once('close',resolve);ws.once('error',reject)});file={path:temp,originalName:path.basename(current.filename),mimeType:current.mime||'application/octet-stream',size:0};}else current.chunks=[];}
  function writeData(chunk){if(!chunk.length)return;total+=chunk.length;if(total>maxBytes)throw new Error('حجم الرفع أكبر من الحد المسموح');if(current?.filename){file.size+=chunk.length;ws.write(chunk)}else if(current)current.chunks.push(Buffer.from(chunk));}
  function finishPart(){if(!current)return;if(current.filename){ws.end();}else{fields[current.name]=Buffer.concat(current.chunks).toString('utf8')}current=null}
  function consume(){
    while(true){
      if(state==='preamble'){
        const i=buf.indexOf(boundary);if(i<0){buf=buf.slice(Math.max(0,buf.length-boundary.length));return}buf=buf.slice(i+boundary.length);if(buf.slice(0,2).toString()==='--'){state='done';return}if(buf.slice(0,2).equals(crlf))buf=buf.slice(2);state='headers';
      } else if(state==='headers'){
        const i=buf.indexOf(Buffer.from('\r\n\r\n'));if(i<0){if(buf.length>8192)throw new Error('رؤوس multipart غير صالحة');return}const h=parseHeaders(buf.slice(0,i));buf=buf.slice(i+4);startPart(h);state='data';
      } else if(state==='data'){
        const i=buf.indexOf(marker);if(i<0){const keep=marker.length+2;if(buf.length<=keep)return;writeData(buf.slice(0,buf.length-keep));buf=buf.slice(buf.length-keep);return}writeData(buf.slice(0,i));buf=buf.slice(i+marker.length);finishPart();if(buf.slice(0,2).toString()==='--'){buf=buf.slice(2);state='done';return}if(buf.slice(0,2).equals(crlf)){buf=buf.slice(2);state='headers';continue}throw new Error('multipart boundary غير صالح');
      } else return;
    }
  }
  return await new Promise((resolve,reject)=>{
    const fail=e=>{if(ended)return;ended=true;try{ws?.destroy();}catch{}try{fs.unlinkSync(temp)}catch{};reject(e)};
    req.on('data',chunk=>{try{buf=Buffer.concat([buf,chunk]);consume()}catch(e){fail(e);req.destroy()}});
    req.on('error',fail);
    req.on('end',()=>{(async()=>{try{if(state!=='done')throw new Error('ملف الرفع غير مكتمل');if(fileClosePromise)await fileClosePromise;if(ended)return;ended=true;resolve({fields,file})}catch(e){fail(e)}})()});
  });
}

function streamVideo(file,res,mime,range){
  const stat=fs.statSync(file); const size=stat.size;
  const headers={'Content-Type':mime,'Accept-Ranges':'bytes','Cache-Control':'private, no-store','Content-Disposition':'inline','X-Content-Type-Options':'nosniff','Content-Length':size};
  if(!range){res.writeHead(200,headers);return fs.createReadStream(file).pipe(res);}
  const m=range.match(/bytes=(\d*)-(\d*)/); if(!m)return text(res,416,'Invalid range'); const start=m[1]?Number(m[1]):0; const end=m[2]?Math.min(Number(m[2]),size-1):size-1; if(start>end||start>=size)return text(res,416,'Invalid range');
  headers['Content-Range']=`bytes ${start}-${end}/${size}`;headers['Content-Length']=end-start+1;res.writeHead(206,headers);fs.createReadStream(file,{start,end}).pipe(res);
}

function serveFile(file,res,type=null,cache=true){if(!fs.existsSync(file))return text(res,404,'Not found');const ext=path.extname(file).toLowerCase();const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8'};const data=fs.readFileSync(file);res.writeHead(200,{'Content-Type':type||types[ext]||'application/octet-stream','Cache-Control':cache?'public, max-age=300':'no-store','Content-Length':data.length});res.end(data)}

const server=http.createServer((req,res)=>handle(req,res).catch(e=>{console.error(e);json(res,500,{error:'حدث خطأ في الخادم'})}));
server.listen(PORT,()=>console.log(`Edu Platform running on http://localhost:${PORT}`));
