import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { db, storage } from './db.js';

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? '' : 'development-only-change-this-secret');
const EDITOR_ACCESS_KEY = process.env.EDITOR_ACCESS_KEY || '';
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 350);
const allowedOrigins = (process.env.CLIENT_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173').split(',').map(x => x.trim()).filter(Boolean);
if (process.env.NODE_ENV === 'production' && (!JWT_SECRET || JWT_SECRET.length < 32)) { console.error('Configure JWT_SECRET com pelo menos 32 caracteres nas variáveis do servidor.'); process.exit(1); }
if (process.env.NODE_ENV === 'production' && !String(process.env.CLIENT_ORIGIN || '').trim()) { console.error('Configure CLIENT_ORIGIN com o domínio público do frontend.'); process.exit(1); }
app.use(cors({ origin: (origin, callback) => { if (!origin || allowedOrigins.includes(origin)) return callback(null, true); return callback(new Error('Origem não autorizada para acessar a API.')); }, credentials: true }));
app.use(express.json({ limit: '2mb' }));
const upload = multer({
  storage: multer.diskStorage({ destination: (_, __, cb) => cb(null, path.join(storage, 'uploads')), filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || '').slice(0, 12).replace(/[^.a-zA-Z0-9]/g, '') || '.bin';
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
  }}),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter: (_, file, cb) => {
    const baseMime = String(file.mimetype || '').split(';')[0].trim().toLowerCase();
    const ext = path.extname(file.originalname || '').toLowerCase();
    const supportedMimes = new Set([
      'video/mp4','video/webm','video/quicktime','video/x-matroska','video/x-msvideo',
      'audio/webm','audio/ogg','audio/mpeg','audio/wav','audio/mp4','audio/x-m4a',
      'image/png','image/jpeg','image/webp','image/gif'
    ]);
    const supportedExtensions = new Set(['.mp4','.webm','.mov','.mkv','.avi','.mp3','.wav','.m4a','.ogg','.png','.jpg','.jpeg','.webp','.gif']);
    // Some Windows browsers report application/octet-stream for otherwise valid local media.
    const ok = supportedMimes.has(baseMime) || (baseMime === 'application/octet-stream' && supportedExtensions.has(ext));
    cb(ok ? null : new Error('Formato de arquivo não suportado. Use MP4, WebM ou MOV para vídeos.'), ok);
  }
});
const publicUser = (u) => u && ({ id: u.id, email: u.email, username: u.username, avatar: u.avatar, editorEnabled: !!u.editor_enabled, createdAt: u.created_at });
const tokenFor = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '14d' });
function auth(req, res, next) {
  const value = req.headers.authorization || '';
  const token = value.startsWith('Bearer ') ? value.slice(7) : ((req.path.startsWith('/api/files/') || req.path.startsWith('/api/exports/')) ? String(req.query.access_token || '') : '');
  if (!token) return res.status(401).json({ error: 'Entre na sua conta para continuar.' });
  try { const data = jwt.verify(token, JWT_SECRET); const user = db.prepare('SELECT * FROM users WHERE id=?').get(data.id); if (!user) return res.status(401).json({ error: 'Sessão inválida.' }); req.user = user; next(); }
  catch { return res.status(401).json({ error: 'Sessão expirada. Entre novamente.' }); }
}
function requireEditor(req, res, next) { if (!req.user.editor_enabled) return res.status(403).json({ error: 'Ative o modo Editor para realizar esta ação.' }); next(); }
function notify(userId, type, title, message = '', link = '') { if (userId) db.prepare('INSERT INTO notifications (user_id,type,title,message,link) VALUES (?,?,?,?,?)').run(userId, type, title, message, link); }
function ownsScene(userId, sceneId) { return !!db.prepare('SELECT 1 FROM scenes WHERE id=? AND owner_id=?').get(sceneId, userId); }
function canReadScene(userId, sceneId) { return !!db.prepare(`SELECT 1 FROM scenes s WHERE s.id=? AND (s.owner_id=? OR s.visibility='public' OR EXISTS(SELECT 1 FROM rooms r JOIN room_participants p ON p.room_id=r.id WHERE r.scene_id=s.id AND p.user_id=? AND r.status<>'closed'))`).get(sceneId, userId, userId); }
function scenePayload(sceneId, userId) {
  const scene = db.prepare(`SELECT s.*, u.username AS owner_username FROM scenes s JOIN users u ON u.id=s.owner_id WHERE s.id=?`).get(sceneId);
  const inRoom = !!db.prepare('SELECT 1 FROM rooms r JOIN room_participants p ON p.room_id=r.id WHERE r.scene_id=? AND p.user_id=? AND r.status<>\'closed\'').get(sceneId,userId);
  if (!scene || !(scene.owner_id === userId || scene.visibility === 'public' || inRoom)) return null;
  const characters = db.prepare('SELECT * FROM characters WHERE scene_id=? ORDER BY sort_order,id').all(sceneId);
  const lines = db.prepare(`SELECT l.*, c.name AS character_name, c.color AS character_color FROM lines l LEFT JOIN characters c ON c.id=l.character_id WHERE l.scene_id=? ORDER BY l.sort_order,l.start_time,l.id`).all(sceneId);
  const media = db.prepare('SELECT id, line_id, user_id, character_id, duration, start_offset, status, take_number, created_at FROM recordings WHERE scene_id=? ORDER BY created_at DESC').all(sceneId);
  return { ...scene, characters, lines, recordings: media, isOwner: scene.owner_id === userId };
}
const friendStatus = (a, b) => db.prepare(`SELECT * FROM friendships WHERE (requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?) ORDER BY id DESC LIMIT 1`).get(a,b,b,a);

app.get('/api/health', (_, res) => res.json({ ok: true, name: 'CenaSync API', time: new Date().toISOString() }));
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { email, password, username, avatar = '🎙️' } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail válido.' });
    if (!password || String(password).length < 8) return res.status(400).json({ error: 'A senha precisa ter pelo menos 8 caracteres.' });
    if (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Use de 3 a 20 caracteres: letras, números ou _.' });
    const password_hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (email,username,password_hash,avatar) VALUES (?,?,?,?)').run(email.trim().toLowerCase(), username.trim(), password_hash, String(avatar).slice(0, 12));
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
    res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
  } catch (e) { if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Este e-mail ou nome de usuário já está em uso.' }); next(e); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const user = db.prepare('SELECT * FROM users WHERE email=? OR username=?').get(String(email || '').trim(), String(email || '').trim());
    if (!user || !(await bcrypt.compare(String(password || ''), user.password_hash))) return res.status(401).json({ error: 'E-mail/nome de usuário ou senha incorretos.' });
    res.json({ token: tokenFor(user), user: publicUser(user) });
  } catch (e) { next(e); }
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.patch('/api/profile', auth, (req, res) => {
  const { avatar, username } = req.body || {};
  if (username && !/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Nome de usuário inválido.' });
  try {
    db.prepare('UPDATE users SET avatar=COALESCE(?,avatar), username=COALESCE(?,username) WHERE id=?').run(avatar ? String(avatar).slice(0,12) : null, username || null, req.user.id);
    res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id)) });
  } catch (e) { if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Esse nome de usuário já existe.' }); res.status(500).json({ error: 'Não foi possível atualizar o perfil.' }); }
});
app.post('/api/editor/activate', auth, (req, res) => {
  if (!EDITOR_ACCESS_KEY) return res.status(503).json({ error: 'O acesso ao modo Editor ainda não foi configurado no servidor.' });
  const ip = String(req.ip || req.socket?.remoteAddress || 'unknown').slice(0, 120);
  const now = Date.now();
  const attempt = db.prepare('SELECT * FROM editor_access_attempts WHERE user_id=? AND ip=?').get(req.user.id, ip);
  const ipAttempt = db.prepare('SELECT * FROM editor_ip_attempts WHERE ip=?').get(ip);
  const windowMs = 15 * 60 * 1000;
  const blockedUntil = Math.max(Number(attempt?.blocked_until)||0, Number(ipAttempt?.blocked_until)||0);
  if (blockedUntil > now) {
    const waitSeconds = Math.max(1, Math.ceil((blockedUntil - now) / 1000));
    res.setHeader('Retry-After', String(waitSeconds));
    return res.status(429).json({ error: `Muitas tentativas. Tente novamente em ${Math.ceil(waitSeconds / 60)} minuto(s).` });
  }
  const recentFailures = attempt && now - Number(attempt.window_started) < windowMs ? Number(attempt.failures) : 0;
  const ipRecentFailures = ipAttempt && now - Number(ipAttempt.window_started) < windowMs ? Number(ipAttempt.failures) : 0;
  if (String(req.body?.password || '') !== EDITOR_ACCESS_KEY) {
    const failures = recentFailures + 1;
    const ipFailures = ipRecentFailures + 1;
    const userBlockedUntil = failures >= 5 ? now + windowMs : 0;
    const ipBlockedUntil = ipFailures >= 10 ? now + windowMs : 0;
    db.prepare(`INSERT INTO editor_access_attempts (user_id,ip,failures,window_started,blocked_until) VALUES (?,?,?,?,?)
      ON CONFLICT(user_id,ip) DO UPDATE SET failures=excluded.failures,window_started=excluded.window_started,blocked_until=excluded.blocked_until`)
      .run(req.user.id, ip, failures >= 5 ? 0 : failures, recentFailures ? attempt.window_started : now, userBlockedUntil);
    db.prepare(`INSERT INTO editor_ip_attempts (ip,failures,window_started,blocked_until) VALUES (?,?,?,?)
      ON CONFLICT(ip) DO UPDATE SET failures=excluded.failures,window_started=excluded.window_started,blocked_until=excluded.blocked_until`)
      .run(ip, ipFailures >= 10 ? 0 : ipFailures, ipRecentFailures ? ipAttempt.window_started : now, ipBlockedUntil);
    if (userBlockedUntil || ipBlockedUntil) {
      res.setHeader('Retry-After', String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ error: 'Limite de tentativas atingido. O acesso ficará bloqueado por 15 minutos.' });
    }
    return res.status(403).json({ error: `Senha de Editor incorreta. ${5 - failures} tentativa(s) restante(s).` });
  }
  db.prepare('DELETE FROM editor_access_attempts WHERE user_id=? AND ip=?').run(req.user.id, ip);
  db.prepare('DELETE FROM editor_ip_attempts WHERE ip=?').run(ip);
  db.prepare('UPDATE users SET editor_enabled=1 WHERE id=?').run(req.user.id);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.json({ user: publicUser(user), message: 'Modo Editor ativado.' });
});

app.get('/api/scenes', auth, (req, res) => {
  const q = String(req.query.q || '').trim();
  const status = String(req.query.status || 'published');
  const rows = db.prepare(`SELECT s.*, u.username AS owner_username, (SELECT COUNT(*) FROM characters c WHERE c.scene_id=s.id) AS character_count,
    (SELECT COUNT(*) FROM lines l WHERE l.scene_id=s.id) AS line_count,
    EXISTS(SELECT 1 FROM favorites f WHERE f.scene_id=s.id AND f.user_id=?) AS is_favorite
    FROM scenes s JOIN users u ON u.id=s.owner_id
    WHERE (s.visibility='public' OR s.owner_id=? OR s.id IN (SELECT scene_id FROM favorites WHERE user_id=?))
    AND (?='' OR s.title LIKE ? OR s.description LIKE ?)
    AND (?='all' OR s.status=? OR s.owner_id=?) ORDER BY s.updated_at DESC LIMIT 200`).all(req.user.id, req.user.id, req.user.id, q, `%${q}%`, `%${q}%`, status, status, req.user.id);
  res.json({ scenes: rows });
});
app.get('/api/scenes/:id', auth, (req, res) => { const data = scenePayload(Number(req.params.id), req.user.id); if (!data) return res.status(404).json({ error: 'Cena não encontrada ou sem acesso.' }); res.json({ scene: data }); });
app.post('/api/scenes', auth, requireEditor, (req, res) => {
  const { title, description = '', source_type = 'upload', source_url = '', source_label = 'Arquivo enviado', duration = 0, language = 'pt-BR', dub_language = 'pt-BR', suggested_cast = 2, visibility = 'private' } = req.body || {};
  if (!String(title || '').trim()) return res.status(400).json({ error: 'Dê um nome para a cena.' });
  const result = db.prepare(`INSERT INTO scenes (owner_id,title,description,source_type,source_url,source_label,duration,language,dub_language,suggested_cast,visibility,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,'draft')`)
    .run(req.user.id, String(title).trim().slice(0,120), String(description).slice(0,2000), source_type, String(source_url).slice(0,1500), String(source_label).slice(0,120), Math.max(0, Number(duration)||0), language, dub_language, Math.max(1, Math.min(30, Number(suggested_cast)||2)), visibility === 'public' ? 'public' : 'private');
  const sceneId = Number(result.lastInsertRowid);
  const c = db.prepare('INSERT INTO characters (scene_id,name,color,avatar,sort_order) VALUES (?,?,?,?,?)');
  const defaultChars = [['Personagem 1','#f05b80','🎭',0],['Personagem 2','#9b7bff','🎙️',1]];
  defaultChars.forEach(x => c.run(sceneId, ...x));
  const ids = db.prepare('SELECT id FROM characters WHERE scene_id=? ORDER BY id').all(sceneId);
  db.prepare('INSERT INTO lines (scene_id,character_id,text,start_time,end_time,sort_order) VALUES (?,?,?,?,?,?)').run(sceneId, ids[0]?.id, 'Escreva aqui a primeira fala...', 0, 2.5, 0);
  res.status(201).json({ scene: scenePayload(sceneId, req.user.id) });
});
app.put('/api/scenes/:id', auth, (req, res) => {
  const id = Number(req.params.id); if (!ownsScene(req.user.id, id)) return res.status(403).json({ error: 'Somente o editor responsável pode alterar esta cena.' });
  const body = req.body || {};
  const scene = db.prepare('SELECT * FROM scenes WHERE id=?').get(id);
  if (body.status === 'published' && !scene.video_path) return res.status(400).json({ error: 'Envie um arquivo de vídeo autorizado para publicar uma cena sincronizável. Links externos servem apenas como referência.' });
  const updated = { title: body.title ?? scene.title, description: body.description ?? scene.description, source_type: body.source_type ?? scene.source_type, source_url: body.source_url ?? scene.source_url, source_label: body.source_label ?? scene.source_label, duration: body.duration ?? scene.duration, clip_start: body.clip_start ?? scene.clip_start, clip_end: body.clip_end ?? scene.clip_end, language: body.language ?? scene.language, dub_language: body.dub_language ?? scene.dub_language, suggested_cast: body.suggested_cast ?? scene.suggested_cast, status: body.status ?? scene.status, visibility: body.visibility ?? scene.visibility };
  db.prepare(`UPDATE scenes SET title=?,description=?,source_type=?,source_url=?,source_label=?,duration=?,clip_start=?,clip_end=?,language=?,dub_language=?,suggested_cast=?,status=?,visibility=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(String(updated.title).slice(0,120), String(updated.description).slice(0,2000), updated.source_type, String(updated.source_url).slice(0,1500), String(updated.source_label).slice(0,120), Math.max(0,Number(updated.duration)||0), Math.max(0,Number(updated.clip_start)||0), Math.max(0,Number(updated.clip_end)||0), updated.language, updated.dub_language, Math.max(1,Math.min(30,Number(updated.suggested_cast)||2)), ['draft','review','published','archived'].includes(updated.status) ? updated.status : 'draft', updated.visibility === 'public' ? 'public':'private', id);
  res.json({ scene: scenePayload(id, req.user.id) });
});
app.put('/api/scenes/:id/editor-state', auth, (req, res) => {
  const id = Number(req.params.id); if (!ownsScene(req.user.id, id)) return res.status(403).json({ error: 'Sem permissão para editar esta cena.' });
  const { characters = [], lines = [], metadata = {} } = req.body || {};
  if (!Array.isArray(characters) || !Array.isArray(lines) || characters.length > 100 || lines.length > 2000) return res.status(400).json({ error: 'A estrutura da cena é inválida.' });
  const save = db.transaction(() => {
    if (metadata.title) db.prepare('UPDATE scenes SET title=?,description=?,duration=?,clip_start=?,clip_end=?,suggested_cast=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(String(metadata.title).slice(0,120), String(metadata.description || '').slice(0,2000), Math.max(0,Number(metadata.duration)||0), Math.max(0,Number(metadata.clip_start)||0), Math.max(0,Number(metadata.clip_end)||0), Math.max(1,Math.min(30,Number(metadata.suggested_cast)||2)), id);
    const oldChars = db.prepare('SELECT id FROM characters WHERE scene_id=?').all(id).map(x=>x.id);
    const keep = new Set(characters.filter(c=>Number(c.id)>0).map(c=>Number(c.id)));
    oldChars.filter(cid=>!keep.has(cid)).forEach(cid=>db.prepare('UPDATE lines SET character_id=NULL WHERE scene_id=? AND character_id=?').run(id,cid));
    db.prepare('DELETE FROM characters WHERE scene_id=? AND id NOT IN ('+(keep.size?[...keep].map(()=>'?').join(','):'-1')+')').run(id,...(keep.size?[...keep]:[]));
    const inserted = []; const charIdMap = new Map();
    const insertChar = db.prepare('INSERT INTO characters (scene_id,name,color,avatar,description,direction,sort_order) VALUES (?,?,?,?,?,?,?)');
    const updateChar = db.prepare('UPDATE characters SET name=?,color=?,avatar=?,description=?,direction=?,sort_order=? WHERE id=? AND scene_id=?');
    for (let i=0;i<characters.length;i++) { const c=characters[i]; let actualId; if (c.id && db.prepare('SELECT 1 FROM characters WHERE id=? AND scene_id=?').get(c.id,id)) { actualId=Number(c.id); updateChar.run(String(c.name||`Personagem ${i+1}`).slice(0,100), c.color||'#f05b80', String(c.avatar||'🎭').slice(0,12), String(c.description||'').slice(0,500), String(c.direction||'').slice(0,1000), i, c.id,id); } else { const r=insertChar.run(id,String(c.name||`Personagem ${i+1}`).slice(0,100),c.color||'#f05b80',String(c.avatar||'🎭').slice(0,12),String(c.description||'').slice(0,500),String(c.direction||'').slice(0,1000),i); actualId=Number(r.lastInsertRowid); } charIdMap.set(String(c.clientKey ?? c.id),actualId); if (c.id) charIdMap.set(String(c.id),actualId); inserted.push({ ...c,id:actualId }); }
    const oldLineIds = db.prepare('SELECT id FROM lines WHERE scene_id=?').all(id).map(x=>x.id);
    const keepLines = new Set(lines.filter(l=>Number(l.id)>0).map(l=>Number(l.id)));
    oldLineIds.filter(lid=>!keepLines.has(lid)).forEach(lid=>db.prepare('DELETE FROM lines WHERE scene_id=? AND id=?').run(id,lid));
    const insLine = db.prepare('INSERT INTO lines (scene_id,character_id,text,start_time,end_time,direction,emotion,pronunciation,status,sort_order) VALUES (?,?,?,?,?,?,?,?,?,?)');
    const updLine = db.prepare('UPDATE lines SET character_id=?,text=?,start_time=?,end_time=?,direction=?,emotion=?,pronunciation=?,status=?,sort_order=? WHERE id=? AND scene_id=?');
    lines.forEach((l,i)=>{ const start=Math.max(0,Number(l.start_time)||0); const end=Math.max(start+0.1,Number(l.end_time)||start+2); const mapped=charIdMap.get(String(l.character_client_key ?? l.character_id)); const charId=mapped || (Number(l.character_id)>0 && db.prepare('SELECT 1 FROM characters WHERE id=? AND scene_id=?').get(Number(l.character_id),id) ? Number(l.character_id) : inserted[0]?.id||null); const vals=[charId,String(l.text||'').slice(0,4000),start,end,String(l.direction||'').slice(0,1000),String(l.emotion||'Neutro').slice(0,80),String(l.pronunciation||'').slice(0,500),['pending','review','approved'].includes(l.status)?l.status:'pending',i]; if (l.id && Number(l.id)>0 && db.prepare('SELECT 1 FROM lines WHERE id=? AND scene_id=?').get(Number(l.id),id)) updLine.run(...vals,Number(l.id),id); else insLine.run(id,...vals); });
  });
  try {
    save();
    const nextVersion = Number(db.prepare('SELECT COALESCE(MAX(version_number),0)+1 AS n FROM scene_versions WHERE scene_id=?').get(id).n);
    db.prepare('INSERT INTO scene_versions (scene_id,version_number,label,snapshot_json,created_by) VALUES (?,?,?,?,?)').run(id,nextVersion,`Versão ${nextVersion}`,JSON.stringify({metadata,characters,lines}),req.user.id);
    db.prepare('DELETE FROM scene_versions WHERE scene_id=? AND id NOT IN (SELECT id FROM scene_versions WHERE scene_id=? ORDER BY version_number DESC LIMIT 50)').run(id,id);
    res.json({ scene: scenePayload(id,req.user.id), message:'Alterações salvas.', version_number:nextVersion });
  } catch(e) { console.error(e); res.status(500).json({ error:'Não foi possível salvar a edição.' }); }
});
app.get('/api/scenes/:id/versions',auth,(req,res)=>{const id=Number(req.params.id);if(!ownsScene(req.user.id,id))return res.status(403).json({error:'Somente o editor responsável pode ver as versões.'});const versions=db.prepare('SELECT v.id,v.version_number,v.label,v.created_at,u.username AS created_by_username FROM scene_versions v LEFT JOIN users u ON u.id=v.created_by WHERE v.scene_id=? ORDER BY v.version_number DESC LIMIT 50').all(id);res.json({versions});});
app.post('/api/scenes/:id/versions/:version/restore',auth,(req,res)=>{const id=Number(req.params.id);if(!ownsScene(req.user.id,id))return res.status(403).json({error:'Somente o editor responsável pode restaurar versões.'});const v=db.prepare('SELECT snapshot_json,version_number FROM scene_versions WHERE scene_id=? AND version_number=?').get(id,Number(req.params.version));if(!v)return res.status(404).json({error:'Essa versão não está disponível.'});try{return res.json({snapshot:JSON.parse(v.snapshot_json),version_number:v.version_number});}catch{return res.status(500).json({error:'A versão salva está corrompida.'});}});
app.post('/api/scenes/:id/media', auth, upload.single('file'), (req,res)=>{
  const id=Number(req.params.id); if(!ownsScene(req.user.id,id)) { if(req.file)fs.unlinkSync(req.file.path); return res.status(403).json({error:'Somente o editor responsável pode enviar mídia.'}); }
  if(!req.file) return res.status(400).json({error:'Selecione um arquivo suportado.'});
  const kind=String(req.body.kind||'video');
  const ext=path.extname(req.file.originalname||'').toLowerCase();
  const mime=String(req.file.mimetype||'').toLowerCase();
  const imageFile=mime.startsWith('image/')||['.png','.jpg','.jpeg','.webp','.gif'].includes(ext);
  const videoFile=mime.startsWith('video/')||['.mp4','.webm','.mov','.mkv','.avi'].includes(ext);
  if(kind==='cover'&&!imageFile){fs.unlinkSync(req.file.path);return res.status(400).json({error:'A capa precisa ser uma imagem PNG, JPG, WebP ou GIF.'});}
  if(kind!=='cover'&&!videoFile){fs.unlinkSync(req.file.path);return res.status(400).json({error:'Envie um arquivo de vídeo MP4, WebM, MOV, MKV ou AVI.'});}
  if(kind==='cover') db.prepare('UPDATE scenes SET cover_path=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(path.basename(req.file.path),id);
  else db.prepare("UPDATE scenes SET video_path=?,source_type=?,source_url='',source_label=?,duration=0,clip_start=0,clip_end=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(path.basename(req.file.path),'upload',req.file.originalname.slice(0,120),id);
  res.json({ file: { name:req.file.originalname, size:req.file.size, mimeType:req.file.mimetype }, scene: scenePayload(id,req.user.id) });
});
app.get('/api/files/:filename', auth, (req,res)=>{
  const filename=path.basename(req.params.filename);
  const scene=db.prepare('SELECT id,owner_id,visibility,video_path,cover_path FROM scenes WHERE video_path=? OR cover_path=?').get(filename,filename);
  const rec=db.prepare('SELECT r.*,s.owner_id,s.visibility FROM recordings r JOIN scenes s ON s.id=r.scene_id WHERE r.file_path=?').get(filename);
  if(scene && (scene.owner_id===req.user.id || scene.visibility==='public' || !!db.prepare(`SELECT 1 FROM rooms r JOIN room_participants p ON p.room_id=r.id WHERE r.scene_id=? AND p.user_id=? AND r.status<>'closed'`).get(scene.id,req.user.id))) return res.sendFile(path.join(storage,'uploads',filename));
  if(rec && (rec.user_id===req.user.id || rec.owner_id===req.user.id || (rec.room_id && !!db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(rec.room_id,req.user.id)))) return res.sendFile(path.join(storage,'uploads',filename));
  return res.status(404).json({error:'Arquivo não encontrado ou sem acesso.'});
});
app.get('/api/scenes/:id/favorite',auth,(req,res)=>{const row=db.prepare('SELECT 1 FROM favorites WHERE user_id=? AND scene_id=?').get(req.user.id,Number(req.params.id));res.json({favorite:!!row});});
app.post('/api/scenes/:id/favorite',auth,(req,res)=>{const id=Number(req.params.id);const existing=db.prepare('SELECT 1 FROM favorites WHERE user_id=? AND scene_id=?').get(req.user.id,id);if(existing)db.prepare('DELETE FROM favorites WHERE user_id=? AND scene_id=?').run(req.user.id,id);else {if(!canReadScene(req.user.id,id))return res.status(404).json({error:'Cena não encontrada.'});db.prepare('INSERT INTO favorites(user_id,scene_id) VALUES(?,?)').run(req.user.id,id);}res.json({favorite:!existing});});
app.delete('/api/scenes/:id',auth,requireEditor,(req,res)=>{
 const id=Number(req.params.id);const scene=db.prepare('SELECT * FROM scenes WHERE id=? AND owner_id=?').get(id,req.user.id);
 if(!scene)return res.status(404).json({error:'Cena não encontrada ou você não é responsável por ela.'});
 if(scene.status==='draft'){
   const files=db.prepare('SELECT file_path FROM recordings WHERE scene_id=? UNION SELECT file_path FROM exports WHERE scene_id=?').all(id,id).map(r=>r.file_path).filter(Boolean);
   [scene.video_path,scene.cover_path,...files].filter(Boolean).forEach(name=>{try{fs.unlinkSync(path.join(storage,'uploads',path.basename(name)));}catch{}});
   db.prepare('DELETE FROM scenes WHERE id=?').run(id);
   return res.json({ok:true,deleted:true});
 }
 db.prepare("UPDATE scenes SET status='archived',visibility='private',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(id);
 res.json({ok:true,deleted:false,message:'Cena arquivada. As gravações foram preservadas.'});
});

app.get('/api/friends',auth,(req,res)=>{
 const rows=db.prepare(`SELECT f.*, CASE WHEN f.requester_id=? THEN f.recipient_id ELSE f.requester_id END AS other_id,
 u.username,u.avatar FROM friendships f JOIN users u ON u.id=CASE WHEN f.requester_id=? THEN f.recipient_id ELSE f.requester_id END
 WHERE f.requester_id=? OR f.recipient_id=? ORDER BY f.created_at DESC`).all(req.user.id,req.user.id,req.user.id,req.user.id);
 res.json({friends:rows.map(f=>({...f, direction:f.requester_id===req.user.id?'sent':'received',user:{id:f.other_id,username:f.username,avatar:f.avatar}}))});
});
app.get('/api/users/search',auth,(req,res)=>{const q=String(req.query.q||'').trim().replace(/^@/,'');if(q.length<2)return res.json({users:[]});const users=db.prepare('SELECT id,username,avatar,editor_enabled,created_at FROM users WHERE username LIKE ? AND id<>? LIMIT 12').all(`%${q}%`,req.user.id);res.json({users:users.map(u=>({...u,editorEnabled:!!u.editor_enabled}))});});
app.post('/api/friends/request',auth,(req,res)=>{
 const target=db.prepare('SELECT id,username FROM users WHERE username=? COLLATE NOCASE').get(String(req.body?.username||'').replace(/^@/,''));if(!target)return res.status(404).json({error:'Usuário não encontrado.'});if(target.id===req.user.id)return res.status(400).json({error:'Você não pode adicionar a si mesmo.'});const f=friendStatus(req.user.id,target.id);if(f&&f.status==='accepted')return res.status(409).json({error:'Vocês já são amigos.'});if(f&&f.status==='pending')return res.status(409).json({error:'Já existe uma solicitação entre vocês.'});
 if(f)db.prepare('DELETE FROM friendships WHERE id=?').run(f.id);db.prepare("INSERT INTO friendships (requester_id,recipient_id,status) VALUES (?,?,'pending')").run(req.user.id,target.id);notify(target.id,'friend_request','Novo pedido de amizade',`@${req.user.username} quer adicionar você.`,'/friends');res.status(201).json({ok:true});
});
app.post('/api/friends/:id/accept',auth,(req,res)=>{const f=db.prepare("SELECT * FROM friendships WHERE id=? AND recipient_id=? AND status='pending'").get(Number(req.params.id),req.user.id);if(!f)return res.status(404).json({error:'Solicitação não encontrada.'});db.prepare("UPDATE friendships SET status='accepted',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(f.id);notify(f.requester_id,'friend_accepted','Pedido aceito',`@${req.user.username} aceitou sua amizade.`,'/friends');res.json({ok:true});});
app.post('/api/friends/:id/decline',auth,(req,res)=>{const f=db.prepare("SELECT * FROM friendships WHERE id=? AND recipient_id=? AND status='pending'").get(Number(req.params.id),req.user.id);if(!f)return res.status(404).json({error:'Solicitação não encontrada.'});db.prepare("UPDATE friendships SET status='declined',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(f.id);res.json({ok:true});});
app.delete('/api/friends/:id',auth,(req,res)=>{const f=db.prepare('SELECT * FROM friendships WHERE id=? AND (requester_id=? OR recipient_id=?)').get(Number(req.params.id),req.user.id,req.user.id);if(!f)return res.status(404).json({error:'Amizade não encontrada.'});db.prepare('DELETE FROM friendships WHERE id=?').run(f.id);res.json({ok:true});});

app.get('/api/rooms',auth,(req,res)=>{const rows=db.prepare(`SELECT r.*,s.title AS scene_title, (SELECT COUNT(*) FROM room_participants p WHERE p.room_id=r.id) AS participant_count,
 (SELECT COUNT(*) FROM room_participants p WHERE p.room_id=r.id AND p.ready=1) AS ready_count FROM rooms r LEFT JOIN scenes s ON s.id=r.scene_id JOIN room_participants mine ON mine.room_id=r.id WHERE mine.user_id=? AND r.status<>'closed' ORDER BY r.created_at DESC`).all(req.user.id);res.json({rooms:rows});});
function roomPayload(roomId,userId){
 const room=db.prepare('SELECT r.*,s.title AS scene_title FROM rooms r LEFT JOIN scenes s ON s.id=r.scene_id WHERE r.id=?').get(roomId);
 if(!room)return null;
 const part=db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(roomId,userId);
 if(!part)return null;
 const participants=db.prepare(`SELECT p.*,u.username,u.avatar,c.name AS character_name,c.color AS character_color,
   rp.line_id AS current_line_id,l.text AS current_line_text FROM room_participants p JOIN users u ON u.id=p.user_id
   LEFT JOIN characters c ON c.id=p.character_id LEFT JOIN room_progress rp ON rp.room_id=p.room_id AND rp.user_id=p.user_id
   LEFT JOIN lines l ON l.id=rp.line_id WHERE p.room_id=? ORDER BY p.joined_at`).all(roomId);
 return {...room,participants:participants.map(p=>({...p,ready:!!p.ready,finished:!!p.finished_at}))};
}
app.post('/api/rooms',auth,(req,res)=>{const sceneId=Number(req.body?.scene_id)||null;let scene=null;if(sceneId){scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(sceneId);if(!scene||!(scene.visibility==='public'||scene.owner_id===req.user.id))return res.status(404).json({error:'Essa cena não está disponível para você.'});}
 let code;do{code=crypto.randomBytes(3).toString('hex').toUpperCase();}while(db.prepare('SELECT 1 FROM rooms WHERE code=?').get(code));const result=db.prepare('INSERT INTO rooms (code,owner_id,scene_id,title) VALUES (?,?,?,?)').run(code,req.user.id,sceneId,String(req.body?.title||`Sessão de ${req.user.username}`).slice(0,100));db.prepare('INSERT INTO room_participants (room_id,user_id,ready) VALUES (?,?,0)').run(result.lastInsertRowid,req.user.id);res.status(201).json({room:roomPayload(Number(result.lastInsertRowid),req.user.id)});});
app.post('/api/rooms/join',auth,(req,res)=>{const code=String(req.body?.code||'').trim().toUpperCase();const room=db.prepare("SELECT * FROM rooms WHERE code=? AND status<>'closed'").get(code);if(!room)return res.status(404).json({error:'Sala não encontrada ou encerrada.'});db.prepare('INSERT INTO room_participants (room_id,user_id,ready) VALUES (?,?,0) ON CONFLICT(room_id,user_id) DO UPDATE SET ready=0').run(room.id,req.user.id);notify(room.owner_id,'room_join',`@${req.user.username} entrou na sala`,`Código ${room.code}`,'/rooms');res.json({room:roomPayload(room.id,req.user.id)});});
app.get('/api/rooms/:id',auth,(req,res)=>{const room=roomPayload(Number(req.params.id),req.user.id);if(!room)return res.status(404).json({error:'Sala não encontrada ou você não participa dela.'});res.json({room});});
app.put('/api/rooms/:id/scene',auth,(req,res)=>{const id=Number(req.params.id);const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(id);if(!room||room.owner_id!==req.user.id)return res.status(403).json({error:'Somente o organizador pode trocar a cena.'});if(room.status!=='lobby')return res.status(409).json({error:'A cena não pode ser alterada depois que a sessão começou.'});const sid=Number(req.body?.scene_id);const scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(sid);if(!scene||!(scene.owner_id===req.user.id||scene.visibility==='public'))return res.status(404).json({error:'Escolha uma cena sua ou publicada na biblioteca.'});db.prepare('UPDATE rooms SET scene_id=? WHERE id=?').run(sid,id);db.prepare('UPDATE room_participants SET ready=0,character_id=NULL WHERE room_id=?').run(id);res.json({room:roomPayload(id,req.user.id)});});
app.post('/api/rooms/:id/invite',auth,(req,res)=>{
 const id=Number(req.params.id);const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(id);
 const member=room&&db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(id,req.user.id);
 if(!room||!member)return res.status(404).json({error:'Sala não encontrada.'});
 if(room.status==='closed')return res.status(409).json({error:'Esta sala já foi encerrada.'});
 const username=String(req.body?.username||'').replace(/^@/,'').trim();
 const target=db.prepare('SELECT id,username FROM users WHERE username=? COLLATE NOCASE').get(username);
 if(!target)return res.status(404).json({error:'Usuário não encontrado.'});
 if(target.id===req.user.id)return res.status(400).json({error:'Você já está nesta sala.'});
 if(db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(id,target.id))return res.status(409).json({error:'Essa pessoa já participa desta sala.'});
 const friendship=friendStatus(req.user.id,target.id);
 if(!friendship||friendship.status!=='accepted')return res.status(403).json({error:'Adicione a pessoa como amiga antes de convidá-la.'});
 const pending=db.prepare("SELECT id FROM room_invites WHERE room_id=? AND recipient_id=? AND status='pending'").get(id,target.id);
 if(pending)return res.status(409).json({error:'Já existe um convite pendente para essa pessoa nesta sala.'});
 db.prepare("INSERT INTO room_invites (room_id,sender_id,recipient_id,status) VALUES (?,?,?,'pending')").run(id,req.user.id,target.id);
 notify(target.id,'room_invite','Convite para dublar',`@${req.user.username} convidou você para a sala ${room.code}.`, `/rooms/${id}?invite=1`);
 res.status(201).json({ok:true,room_id:id,username:target.username,message:'Convite enviado. A pessoa entrará nesta mesma sala ao aceitá-lo.'});
});
app.post('/api/rooms/:id/accept-invite',auth,(req,res)=>{
 const id=Number(req.params.id);const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(id);
 if(!room||room.status==='closed')return res.status(404).json({error:'Sala não encontrada ou encerrada.'});
 // Idempotent acceptance: reopening a notification after accepting should not create a fake second room or fail.
 if(db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(id,req.user.id))return res.json({room:roomPayload(id,req.user.id),alreadyMember:true});
 const invite=db.prepare("SELECT * FROM room_invites WHERE room_id=? AND recipient_id=? AND status='pending' ORDER BY id DESC LIMIT 1").get(id,req.user.id);
 if(!invite)return res.status(403).json({error:'Não existe convite pendente para você nesta sala.'});
 db.transaction(()=>{
   db.prepare("UPDATE room_invites SET status='accepted',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(invite.id);
   db.prepare('INSERT INTO room_participants (room_id,user_id,ready) VALUES (?,?,0) ON CONFLICT(room_id,user_id) DO NOTHING').run(id,req.user.id);
 })( );
 res.json({room:roomPayload(id,req.user.id)});
});
app.get('/api/rooms/:id/messages',auth,(req,res)=>{
 const id=Number(req.params.id);if(!roomPayload(id,req.user.id))return res.status(404).json({error:'Sala não encontrada.'});
 const messages=db.prepare(`SELECT m.id,m.user_id,m.message,m.created_at,u.username,u.avatar FROM room_messages m JOIN users u ON u.id=m.user_id WHERE m.room_id=? ORDER BY m.id DESC LIMIT 100`).all(id).reverse();
 res.json({messages});
});
app.post('/api/rooms/:id/messages',auth,(req,res)=>{
 const id=Number(req.params.id);if(!roomPayload(id,req.user.id))return res.status(404).json({error:'Sala não encontrada.'});
 const message=String(req.body?.message||'').trim();if(!message)return res.status(400).json({error:'Escreva uma mensagem.'});if(message.length>1000)return res.status(400).json({error:'A mensagem pode ter até 1000 caracteres.'});
 const result=db.prepare('INSERT INTO room_messages (room_id,user_id,message) VALUES (?,?,?)').run(id,req.user.id,message);
 res.status(201).json({message:db.prepare('SELECT m.*,u.username,u.avatar FROM room_messages m JOIN users u ON u.id=m.user_id WHERE m.id=?').get(result.lastInsertRowid)});
});
app.patch('/api/rooms/:id/progress',auth,(req,res)=>{
 const id=Number(req.params.id);const room=roomPayload(id,req.user.id);if(!room)return res.status(404).json({error:'Sala não encontrada.'});
 const lineId=Number(req.body?.line_id)||null;if(lineId&&!db.prepare('SELECT 1 FROM lines WHERE id=? AND scene_id=?').get(lineId,room.scene_id))return res.status(400).json({error:'Fala inválida para esta sala.'});
 db.prepare(`INSERT INTO room_progress (room_id,user_id,line_id) VALUES (?,?,?) ON CONFLICT(room_id,user_id) DO UPDATE SET line_id=excluded.line_id,updated_at=CURRENT_TIMESTAMP`).run(id,req.user.id,lineId);
 res.json({ok:true});
});
app.post('/api/rooms/:id/finish',auth,(req,res)=>{
 const id=Number(req.params.id);if(!roomPayload(id,req.user.id))return res.status(404).json({error:'Sala não encontrada.'});
 db.prepare('UPDATE room_participants SET finished_at=CURRENT_TIMESTAMP WHERE room_id=? AND user_id=?').run(id,req.user.id);
 res.json({room:roomPayload(id,req.user.id)});
});
app.get('/api/rooms/:id/exports',auth,(req,res)=>{
 const id=Number(req.params.id);const room=roomPayload(id,req.user.id);if(!room)return res.status(404).json({error:'Sala não encontrada.'});
 const item=db.prepare('SELECT * FROM exports WHERE room_id=? ORDER BY id DESC LIMIT 1').get(id);
 const allFinished=room.participants.length>0&&room.participants.every(p=>p.finished);
 res.json({export:item?{...item,downloadUrl:item.status==='completed'?`/api/exports/${item.id}/download`:null}:null,allFinished,room});
});
app.patch('/api/rooms/:id/ready',auth,(req,res)=>{const id=Number(req.params.id);if(!roomPayload(id,req.user.id))return res.status(404).json({error:'Sala não encontrada.'});const characterId=Number(req.body?.character_id)||null;if(characterId){const room=db.prepare('SELECT scene_id FROM rooms WHERE id=?').get(id);if(!db.prepare('SELECT 1 FROM characters WHERE id=? AND scene_id=?').get(characterId,room.scene_id))return res.status(400).json({error:'Personagem inválido para esta cena.'});}db.prepare('UPDATE room_participants SET ready=?,character_id=?,finished_at=NULL WHERE room_id=? AND user_id=?').run(req.body?.ready?1:0,characterId,id,req.user.id);res.json({room:roomPayload(id,req.user.id)});});
app.post('/api/rooms/:id/start',auth,(req,res)=>{const id=Number(req.params.id);const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(id);if(!room||room.owner_id!==req.user.id)return res.status(403).json({error:'Somente quem criou a sala pode iniciar a sessão.'});const ps=db.prepare('SELECT * FROM room_participants WHERE room_id=?').all(id);if(ps.length===0||ps.some(p=>!p.ready))return res.status(400).json({error:'Todos os participantes precisam marcar que estão prontos.'});db.prepare("UPDATE rooms SET status='recording' WHERE id=?").run(id);res.json({room:roomPayload(id,req.user.id)});});
app.post('/api/rooms/:id/close',auth,(req,res)=>{const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(Number(req.params.id));if(!room||room.owner_id!==req.user.id)return res.status(403).json({error:'Somente o organizador pode encerrar a sala.'});db.prepare("UPDATE rooms SET status='closed' WHERE id=?").run(room.id);res.json({ok:true});});

const waveformCache = new Map();
app.get('/api/scenes/:id/waveform',auth,async(req,res)=>{
 const id=Number(req.params.id);const scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(id);
 if(!scene||!canReadScene(req.user.id,id))return res.status(404).json({error:'Cena não encontrada.'});
 if(!scene.video_path)return res.status(400).json({error:'Envie um arquivo de vídeo para analisar o áudio real.'});
 const video=path.join(storage,'uploads',path.basename(scene.video_path));if(!fs.existsSync(video))return res.status(404).json({error:'O arquivo de vídeo não está disponível.'});
 const stat=fs.statSync(video);const key=`${id}:${scene.video_path}:${stat.size}:${stat.mtimeMs}`;const cached=waveformCache.get(key);if(cached)return res.json(cached);
 const child=spawn('ffmpeg',['-v','error','-i',video,'-vn','-ac','1','-ar','1000','-f','s16le','pipe:1'],{stdio:['ignore','pipe','pipe']});
 const chunks=[];let bytes=0;let stderr='';let failed=false;
 child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>45*1024*1024){failed=true;child.kill('SIGKILL');return;}chunks.push(chunk);});
 child.stderr.on('data',x=>{stderr+=x.toString().slice(0,1000);});
 child.on('error',err=>res.status(503).json({error:err.code==='ENOENT'?'A análise de waveform exige FFmpeg instalado no servidor.':'Não foi possível analisar o áudio.'}));
 child.on('close',code=>{
  if(res.headersSent)return;
  if(failed)return res.status(413).json({error:'O vídeo é longo demais para gerar a waveform de uma vez. Tente um trecho menor.'});
  if(code!==0)return res.json({duration:0,samples:[],hasAudio:false,note:'Não foi encontrada uma faixa de áudio legível neste vídeo.'});
  const buffer=Buffer.concat(chunks);const count=Math.floor(buffer.length/2);if(!count)return res.json({duration:0,samples:[],hasAudio:false});
  const target=320;const samples=[];const view=new DataView(buffer.buffer,buffer.byteOffset,buffer.byteLength);
  for(let bucket=0;bucket<target;bucket++){const from=Math.floor(bucket*count/target);const to=Math.max(from+1,Math.floor((bucket+1)*count/target));let peak=0;for(let i=from;i<Math.min(to,count);i++){peak=Math.max(peak,Math.abs(view.getInt16(i*2,true))/32768);}samples.push(Number(peak.toFixed(3)));}
  const result={duration:count/1000,samples,hasAudio:true};waveformCache.set(key,result);res.json(result);
 });
});
app.post('/api/scenes/:id/analyze',auth,requireEditor,async(req,res)=>{
 const id=Number(req.params.id);const scene=db.prepare('SELECT * FROM scenes WHERE id=? AND owner_id=?').get(id,req.user.id);
 if(!scene)return res.status(404).json({error:'Cena não encontrada.'});
 if(!scene.video_path)return res.status(400).json({error:'Envie um arquivo de vídeo antes de analisar falas e personagens.'});
 if(!process.env.OPENAI_API_KEY)return res.status(503).json({error:'A análise de falas por IA não está configurada. Adicione OPENAI_API_KEY nas variáveis privadas do servidor.'});
 const video=path.join(storage,'uploads',path.basename(scene.video_path));if(!fs.existsSync(video))return res.status(404).json({error:'O arquivo de vídeo não está disponível.'});
 const temp=path.join(storage,'uploads',`analysis-${crypto.randomBytes(10).toString('hex')}.mp3`);
 const child=spawn('ffmpeg',['-y','-v','error','-i',video,'-vn','-ac','1','-ar','16000','-b:a','48k',temp],{stdio:'ignore'});
 child.on('error',err=>{try{fs.unlinkSync(temp);}catch{};res.status(503).json({error:err.code==='ENOENT'?'A análise por IA exige FFmpeg instalado no servidor.':'Não foi possível preparar o áudio para análise.'});});
 child.on('close',async(code)=>{
  try{
   if(res.headersSent)return;
   if(code!==0||!fs.existsSync(temp))return res.status(422).json({error:'Não foi possível extrair o áudio deste vídeo. Verifique se ele possui uma faixa de áudio.'});
   const stat=fs.statSync(temp);if(stat.size>24*1024*1024)return res.status(413).json({error:'O áudio extraído excedeu o limite de 24 MB da análise. Divida o vídeo em trechos menores.'});
   const form=new FormData();form.append('file',new Blob([fs.readFileSync(temp)],{type:'audio/mpeg'}),'scene.mp3');form.append('model','gpt-4o-transcribe-diarize');form.append('response_format','diarized_json');form.append('chunking_strategy','auto');
   const response=await fetch('https://api.openai.com/v1/audio/transcriptions',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`},body:form});
   const payload=await response.json().catch(()=>({}));if(!response.ok)return res.status(response.status===401?503:502).json({error:payload.error?.message||'O serviço de transcrição não conseguiu analisar este áudio.'});
   const segments=Array.isArray(payload.segments)?payload.segments:[];
   const speakerLabels=new Map();
   const normalized=segments.filter(s=>String(s.text||'').trim()).map((s,i)=>{
     const rawSpeaker=String(s.speaker_id||s.speaker||'speaker_0');
     if(!speakerLabels.has(rawSpeaker))speakerLabels.set(rawSpeaker,`Voz ${speakerLabels.size+1}`);
     const start=Math.max(0,Number(s.start)||0);
     return {id:s.id||i,text:String(s.text||'').trim(),start,end:Math.max(start+0.15,Number(s.end)||start+1),speaker:speakerLabels.get(rawSpeaker),speaker_id:rawSpeaker};
   });
   const cuts=[];
   for(let i=1;i<normalized.length;i++){const gap=normalized[i].start-normalized[i-1].end;if(gap>=1.25)cuts.push({start:Number(normalized[i-1].end.toFixed(2)),end:Number(normalized[i].start.toFixed(2)),duration:Number(gap.toFixed(2)),reason:'Pausa detectada entre falas; revise visualmente antes de usar.'});}
   res.json({text:payload.text||'',segments:normalized,suggestedCuts:cuts,model:'gpt-4o-transcribe-diarize',note:'A IA transcreve e separa vozes audíveis. Os rótulos Voz 1, Voz 2 etc. não identificam visualmente o nome de personagens; revise a atribuição antes de salvar. Os cortes são sugestões baseadas em pausas.'});
  }catch(err){if(!res.headersSent)res.status(502).json({error:'A análise por IA falhou. Verifique a chave e tente novamente.'});}
  finally{try{fs.unlinkSync(temp);}catch{}}
 });
});

app.get('/api/scenes/:id/recordings',auth,(req,res)=>{const sceneId=Number(req.params.id);if(!canReadScene(req.user.id,sceneId))return res.status(404).json({error:'Cena não encontrada.'});const rows=db.prepare(`SELECT r.*,u.username,u.avatar,c.name AS character_name,l.text AS line_text FROM recordings r JOIN users u ON u.id=r.user_id LEFT JOIN characters c ON c.id=r.character_id JOIN lines l ON l.id=r.line_id WHERE r.scene_id=? ORDER BY r.created_at DESC`).all(sceneId);res.json({recordings:rows.map(r=>({...r,url:`/api/files/${encodeURIComponent(path.basename(r.file_path))}`}))});});
app.post('/api/scenes/:id/recordings',auth,upload.single('file'),(req,res)=>{const sceneId=Number(req.params.id);if(!req.file)return res.status(400).json({error:'Nenhuma gravação foi recebida.'});const recExt=path.extname(req.file.originalname||'').toLowerCase();const recMime=String(req.file.mimetype||'').toLowerCase();if(!recMime.startsWith('audio/')&&!(recMime==='application/octet-stream'&&['.mp3','.wav','.m4a','.ogg','.weba'].includes(recExt))){fs.unlinkSync(req.file.path);return res.status(400).json({error:'A tomada precisa ser um arquivo de áudio gravado pelo microfone.'});}const lineId=Number(req.body?.line_id);const line=db.prepare('SELECT l.*,s.owner_id,s.visibility FROM lines l JOIN scenes s ON s.id=l.scene_id WHERE l.id=? AND l.scene_id=?').get(lineId,sceneId);const roomId=Number(req.body?.room_id)||null;const roomAccess=roomId && !!db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(roomId,req.user.id) && !!db.prepare('SELECT 1 FROM rooms WHERE id=? AND scene_id=? AND status<>\'closed\'').get(roomId,sceneId);if(!line || (roomId&&!roomAccess) || !(line.owner_id===req.user.id || line.visibility==='public' || roomAccess)){fs.unlinkSync(req.file.path);return res.status(403).json({error:'Você não pode enviar uma gravação para essa fala ou sala.'});}const characterId=Number(req.body?.character_id)||line.character_id;const take=db.prepare('SELECT COALESCE(MAX(take_number),0)+1 AS n FROM recordings WHERE line_id=? AND user_id=?').get(lineId,req.user.id).n;const result=db.prepare('INSERT INTO recordings (scene_id,room_id,line_id,user_id,character_id,file_path,mime_type,duration,start_offset,take_number) VALUES (?,?,?,?,?,?,?,?,?,?)').run(sceneId,roomId,lineId,req.user.id,characterId,path.basename(req.file.path),req.file.mimetype,Math.max(0,Number(req.body?.duration)||0),Math.max(0,Number(req.body?.start_offset)||line.start_time),take);if(roomId)db.prepare('UPDATE room_participants SET finished_at=NULL WHERE room_id=? AND user_id=?').run(roomId,req.user.id);const owner=line.owner_id;if(owner!==req.user.id)notify(owner,'recording','Nova tomada enviada',`@${req.user.username} enviou uma gravação.`,'/editor');res.status(201).json({recording:db.prepare('SELECT * FROM recordings WHERE id=?').get(result.lastInsertRowid)});});
app.patch('/api/recordings/:id/approve',auth,(req,res)=>{const rec=db.prepare('SELECT r.*,s.owner_id FROM recordings r JOIN scenes s ON s.id=r.scene_id WHERE r.id=?').get(Number(req.params.id));if(!rec)return res.status(404).json({error:'Tomada não encontrada.'});if(rec.owner_id!==req.user.id)return res.status(403).json({error:'Somente o editor pode aprovar uma tomada.'});db.prepare("UPDATE recordings SET status='approved' WHERE id=?").run(rec.id);db.prepare("UPDATE lines SET status='approved' WHERE id=?").run(rec.line_id);notify(rec.user_id,'recording_approved','Tomada aprovada','O editor aprovou sua gravação.','/library');res.json({ok:true});});
app.post('/api/scenes/:id/feedback',auth,(req,res)=>{const sceneId=Number(req.params.id);const scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(sceneId);const roomAccess=!!db.prepare(`SELECT 1 FROM rooms r JOIN room_participants p ON p.room_id=r.id WHERE r.scene_id=? AND p.user_id=? AND r.status<>'closed'`).get(sceneId,req.user.id);if(!scene||!(scene.visibility==='public'||scene.owner_id===req.user.id||roomAccess))return res.status(404).json({error:'Cena não encontrada.'});const {line_id=null,category='other',message=''}=req.body||{};if(String(message).trim().length<5)return res.status(400).json({error:'Descreva o problema com pelo menos 5 caracteres.'});const result=db.prepare('INSERT INTO feedback (scene_id,line_id,sender_id,assignee_id,category,message) VALUES (?,?,?,?,?,?)').run(sceneId,line_id,req.user.id,scene.owner_id,String(category).slice(0,80),String(message).slice(0,3000));if(scene.owner_id!==req.user.id)notify(scene.owner_id,'feedback','Nova solicitação de correção',String(message).slice(0,140),'/feedback');res.status(201).json({feedback:db.prepare('SELECT * FROM feedback WHERE id=?').get(result.lastInsertRowid)});});
app.get('/api/feedback',auth,(req,res)=>{const rows=db.prepare(`SELECT f.*,s.title AS scene_title,l.text AS line_text, sender.username AS sender_username,assignee.username AS assignee_username FROM feedback f JOIN scenes s ON s.id=f.scene_id LEFT JOIN lines l ON l.id=f.line_id JOIN users sender ON sender.id=f.sender_id JOIN users assignee ON assignee.id=f.assignee_id WHERE f.sender_id=? OR f.assignee_id=? ORDER BY CASE f.status WHEN 'pending' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,f.created_at DESC`).all(req.user.id,req.user.id);res.json({feedback:rows});});
app.patch('/api/feedback/:id',auth,(req,res)=>{const f=db.prepare('SELECT * FROM feedback WHERE id=?').get(Number(req.params.id));if(!f)return res.status(404).json({error:'Solicitação não encontrada.'});if(f.assignee_id!==req.user.id&&f.sender_id!==req.user.id)return res.status(403).json({error:'Sem permissão.'});const status=['pending','in_progress','fixed','closed'].includes(req.body?.status)?req.body.status:f.status;const response=String(req.body?.response??f.response).slice(0,3000);db.prepare('UPDATE feedback SET status=?,response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,response,f.id);if(f.sender_id!==req.user.id)notify(f.sender_id,'feedback_reply','Sua solicitação foi atualizada',response||'O editor atualizou o status da solicitação.','/feedback');res.json({feedback:db.prepare('SELECT * FROM feedback WHERE id=?').get(f.id)});});
app.get('/api/notifications',auth,(req,res)=>{res.json({notifications:db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.user.id)});});
app.post('/api/notifications/read-all',auth,(req,res)=>{db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(req.user.id);res.json({ok:true});});

// Final MP4 export is performed with FFmpeg when it is installed and the scene has an uploaded video.
function probeHasAudio(filePath) {
 return new Promise(resolve=>{
  let stdout='';
  const probe=spawn('ffprobe',['-v','error','-select_streams','a:0','-show_entries','stream=codec_type','-of','csv=p=0',filePath],{stdio:['ignore','pipe','ignore']});
  probe.stdout.on('data',chunk=>{stdout+=chunk.toString();});
  probe.on('error',()=>resolve(false));
  probe.on('close',code=>resolve(code===0&&stdout.trim().length>0));
 });
}
app.post('/api/scenes/:id/export',auth,(req,res)=>{
 const id=Number(req.params.id);
 const requestedRoomId=Number(req.body?.room_id)||null;
 const scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(id);
 if(!scene)return res.status(404).json({error:'Cena não encontrada.'});
 let roomAccess=false;
 if(requestedRoomId){
   roomAccess=!!db.prepare("SELECT 1 FROM rooms r JOIN room_participants p ON p.room_id=r.id WHERE r.id=? AND r.scene_id=? AND p.user_id=? AND r.status<>'closed'").get(requestedRoomId,id,req.user.id);
   if(!roomAccess)return res.status(403).json({error:'Você não participa desta sala ou a sala não corresponde à cena.'});
   const room=roomPayload(requestedRoomId,req.user.id);
   if(!room||!room.participants.length||!room.participants.every(p=>p.finished))return res.status(409).json({error:'Todos os participantes precisam finalizar suas falas antes de montar o vídeo.'});
 }
 if(!(scene.owner_id===req.user.id||roomAccess))return res.status(403).json({error:'Somente o responsável pela cena ou um participante da sala pode exportar.'});
 if(!scene.video_path)return res.status(400).json({error:'Para exportar um MP4, envie primeiro um arquivo de vídeo autorizado. Links incorporados não são exportáveis por padrão.'});
 const video=path.join(storage,'uploads',path.basename(scene.video_path));
 if(!fs.existsSync(video))return res.status(400).json({error:'O arquivo de vídeo original não está disponível.'});
 const result=db.prepare("INSERT INTO exports (scene_id,user_id,room_id,status) VALUES (?,?,?,'queued')").run(id,req.user.id,roomAccess?requestedRoomId:null);
 const exportId=Number(result.lastInsertRowid);
 const output=path.join(storage,'uploads',`export-${exportId}-${Date.now()}.mp4`);
 const clipStart=Math.max(0,Number(scene.clip_start)||0);
 const clipEnd=Math.max(0,Number(scene.clip_end)||0);
 const fullDuration=Math.max(0,Number(scene.duration)||0);
 const outputDuration=clipEnd>clipStart?clipEnd-clipStart:(fullDuration>clipStart?fullDuration-clipStart:0);
 const roomFilter=roomAccess?requestedRoomId:null;
 const recs=db.prepare(`
   WITH ranked AS (
     SELECT r.*,l.start_time,
       ROW_NUMBER() OVER (PARTITION BY r.line_id ORDER BY CASE WHEN r.status='approved' THEN 0 ELSE 1 END,r.id DESC) AS take_rank
     FROM recordings r JOIN lines l ON l.id=r.line_id
     WHERE r.scene_id=? AND ((? IS NULL AND r.room_id IS NULL) OR r.room_id=?)
   )
   SELECT * FROM ranked WHERE take_rank=1 ORDER BY start_time,id
 `).all(id,roomFilter,roomFilter);
 const valid=[];
 for(const r of recs){
   const file=path.join(storage,'uploads',path.basename(r.file_path));
   if(fs.existsSync(file))valid.push({...r,absolutePath:file});
 }
 db.prepare("UPDATE exports SET status='processing' WHERE id=?").run(exportId);
 res.status(202).json({export:{id:exportId,status:'processing'},message:'A exportação começou. Acompanhe o resultado nesta sala.'});
 const fail=(message)=>db.prepare("UPDATE exports SET status='failed',error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?").run(String(message||'Falha ao exportar o vídeo.').slice(0,1000),exportId);
 void probeHasAudio(video).then(hasOriginalAudio=>{
   const args=['-y'];
   if(clipStart>0)args.push('-ss',String(clipStart));
   args.push('-i',video);
   valid.forEach(r=>{
     const absoluteStart=Math.max(0,Number(r.start_offset)||Number(r.start_time)||0);
     const delay=Math.max(0,Math.round((absoluteStart-clipStart)*1000));
     args.push('-i',r.absolutePath);
     r.delay=delay;
   });
   const filters=[];
   const mixInputs=[];
   valid.forEach((r,i)=>{
     filters.push(`[${i+1}:a:0]adelay=${r.delay}|${r.delay},volume=1.0[voice${i}]`);
     mixInputs.push(`[voice${i}]`);
   });
   const keepOriginal=!!req.body?.keep_original&&hasOriginalAudio;
   if(keepOriginal&&mixInputs.length){
     filters.push('[0:a:0]volume=0.22[original]');
     mixInputs.push('[original]');
   }
   if(mixInputs.length){
     filters.push(`${mixInputs.join('')}amix=inputs=${mixInputs.length}:duration=longest:dropout_transition=2[aout]`);
     args.push('-filter_complex',filters.join(';'),'-map','0:v:0','-map','[aout]','-c:v','libx264','-preset','veryfast','-crf','20','-pix_fmt','yuv420p','-c:a','aac');
   }else{
     args.push('-map','0:v:0','-c:v','libx264','-preset','veryfast','-crf','20','-pix_fmt','yuv420p');
     if(keepOriginal)args.push('-map','0:a:0','-c:a','aac');else args.push('-an');
   }
   if(outputDuration>0)args.push('-t',String(outputDuration));
   args.push('-movflags','+faststart',output);
   const child=spawn('ffmpeg',args,{stdio:'ignore'});
   child.once('error',err=>fail(err.code==='ENOENT'?'FFmpeg não encontrado. Instale FFmpeg e coloque-o no PATH.':err.message));
   child.once('close',code=>{
     if(code===0&&fs.existsSync(output))db.prepare("UPDATE exports SET status='completed',file_path=?,error='',finished_at=CURRENT_TIMESTAMP WHERE id=?").run(path.basename(output),exportId);
     else fail('FFmpeg encerrou com erro. Verifique os codecs do arquivo e a existência de faixas de áudio.');
   });
 }).catch(()=>fail('Não foi possível preparar a exportação.'));
});
function exportAccess(exportId,userId){const e=db.prepare('SELECT * FROM exports WHERE id=?').get(exportId);if(!e)return null;if(e.user_id===userId)return e;if(e.room_id&&db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(e.room_id,userId))return e;return null;}
app.get('/api/exports/:id',auth,(req,res)=>{const e=exportAccess(Number(req.params.id),req.user.id);if(!e)return res.status(404).json({error:'Exportação não encontrada.'});res.json({export:{...e,streamUrl:e.status==='completed'?`/api/exports/${e.id}/stream`:null,downloadUrl:e.status==='completed'?`/api/exports/${e.id}/download`:null}});});
app.get('/api/exports/:id/stream',auth,(req,res)=>{const e=exportAccess(Number(req.params.id),req.user.id);if(!e||e.status!=='completed'||!e.file_path)return res.status(404).json({error:'Vídeo ainda não está pronto ou você não tem acesso.'});res.sendFile(path.join(storage,'uploads',path.basename(e.file_path)));});
app.get('/api/exports/:id/download',auth,(req,res)=>{const e=exportAccess(Number(req.params.id),req.user.id);if(!e||e.status!=='completed'||!e.file_path)return res.status(404).json({error:'Arquivo ainda não está pronto ou você não tem acesso.'});res.download(path.join(storage,'uploads',path.basename(e.file_path)),`cenasync-export-${e.id}.mp4`);});

const clientDist = path.resolve(process.cwd(), '../client/dist');
if (fs.existsSync(path.join(clientDist, 'index.html'))) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(clientDist, 'index.html')); });
}

app.use((err,req,res,_next)=>{console.error(err);if(err instanceof multer.MulterError)return res.status(err.code==='LIMIT_FILE_SIZE'?413:400).json({error:err.code==='LIMIT_FILE_SIZE'?`O arquivo ultrapassa o limite de ${MAX_UPLOAD_MB} MB.`:'Não foi possível processar o upload.'});if(String(err?.message||'').includes('Formato de arquivo não suportado'))return res.status(415).json({error:err.message});res.status(500).json({error:err.message||'Erro interno. Tente novamente.'});});
app.listen(PORT,()=>console.log(`CenaSync API ativa em http://localhost:${PORT}`));
