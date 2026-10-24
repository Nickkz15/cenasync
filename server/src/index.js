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
const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET || 'development-only-change-this-secret';
const EDITOR_ACCESS_KEY = process.env.EDITOR_ACCESS_KEY || '';
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 350);
const allowedOrigins = (process.env.CLIENT_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin: (origin, callback) => { if (!origin || allowedOrigins.includes(origin)) return callback(null, true); return callback(new Error('Origem não autorizada para acessar a API.')); }, credentials: true }));
app.use(express.json({ limit: '2mb' }));
const upload = multer({
  storage: multer.diskStorage({ destination: (_, __, cb) => cb(null, path.join(storage, 'uploads')), filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || '').slice(0, 12).replace(/[^.a-zA-Z0-9]/g, '') || '.bin';
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
  }}),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter: (_, file, cb) => {
    const allowed = /^(video\/(mp4|webm|quicktime|x-matroska)|audio\/(webm|ogg|mpeg|wav|mp4|x-m4a)|image\/(png|jpeg|webp|gif))$/i;
    const baseMime = String(file.mimetype || '').split(';')[0].trim();
    cb(allowed.test(baseMime) ? null : new Error('Formato de arquivo não suportado.'), allowed.test(baseMime));
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
  if (!EDITOR_ACCESS_KEY || String(req.body?.password || '') !== EDITOR_ACCESS_KEY) {
    return res.status(403).json({ error: 'Senha de Editor incorreta.' });
  }
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
  if(kind==='cover') db.prepare('UPDATE scenes SET cover_path=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(path.basename(req.file.path),id);
  else db.prepare('UPDATE scenes SET video_path=?,source_type=?,source_label=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(path.basename(req.file.path),'upload',req.file.originalname.slice(0,120),id);
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
app.delete('/api/scenes/:id',auth,requireEditor,(req,res)=>{const id=Number(req.params.id);if(!ownsScene(req.user.id,id))return res.status(403).json({error:'Você não é responsável por esta cena.'});db.prepare("UPDATE scenes SET status='archived',visibility='private',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(id);res.json({ok:true});});

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
function roomPayload(roomId,userId){const room=db.prepare('SELECT r.*,s.title AS scene_title FROM rooms r LEFT JOIN scenes s ON s.id=r.scene_id WHERE r.id=?').get(roomId);if(!room)return null;const part=db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(roomId,userId);if(!part)return null;const participants=db.prepare('SELECT p.*,u.username,u.avatar,c.name AS character_name,c.color AS character_color FROM room_participants p JOIN users u ON u.id=p.user_id LEFT JOIN characters c ON c.id=p.character_id WHERE p.room_id=? ORDER BY p.joined_at').all(roomId);return {...room,participants:participants.map(p=>({...p,ready:!!p.ready}))};}
app.post('/api/rooms',auth,(req,res)=>{const sceneId=Number(req.body?.scene_id)||null;let scene=null;if(sceneId){scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(sceneId);if(!scene||!(scene.visibility==='public'||scene.owner_id===req.user.id))return res.status(404).json({error:'Essa cena não está disponível para você.'});}
 let code;do{code=crypto.randomBytes(3).toString('hex').toUpperCase();}while(db.prepare('SELECT 1 FROM rooms WHERE code=?').get(code));const result=db.prepare('INSERT INTO rooms (code,owner_id,scene_id,title) VALUES (?,?,?,?)').run(code,req.user.id,sceneId,String(req.body?.title||`Sessão de ${req.user.username}`).slice(0,100));db.prepare('INSERT INTO room_participants (room_id,user_id,ready) VALUES (?,?,0)').run(result.lastInsertRowid,req.user.id);res.status(201).json({room:roomPayload(Number(result.lastInsertRowid),req.user.id)});});
app.post('/api/rooms/join',auth,(req,res)=>{const code=String(req.body?.code||'').trim().toUpperCase();const room=db.prepare("SELECT * FROM rooms WHERE code=? AND status<>'closed'").get(code);if(!room)return res.status(404).json({error:'Sala não encontrada ou encerrada.'});db.prepare('INSERT INTO room_participants (room_id,user_id,ready) VALUES (?,?,0) ON CONFLICT(room_id,user_id) DO UPDATE SET ready=0').run(room.id,req.user.id);notify(room.owner_id,'room_join',`@${req.user.username} entrou na sala`,`Código ${room.code}`,'/rooms');res.json({room:roomPayload(room.id,req.user.id)});});
app.get('/api/rooms/:id',auth,(req,res)=>{const room=roomPayload(Number(req.params.id),req.user.id);if(!room)return res.status(404).json({error:'Sala não encontrada ou você não participa dela.'});res.json({room});});
app.put('/api/rooms/:id/scene',auth,(req,res)=>{const id=Number(req.params.id);const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(id);if(!room||room.owner_id!==req.user.id)return res.status(403).json({error:'Somente o organizador pode trocar a cena.'});if(room.status!=='lobby')return res.status(409).json({error:'A cena não pode ser alterada depois que a sessão começou.'});const sid=Number(req.body?.scene_id);const scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(sid);if(!scene||!(scene.owner_id===req.user.id||scene.visibility==='public'))return res.status(404).json({error:'Escolha uma cena sua ou publicada na biblioteca.'});db.prepare('UPDATE rooms SET scene_id=? WHERE id=?').run(sid,id);db.prepare('UPDATE room_participants SET ready=0,character_id=NULL WHERE room_id=?').run(id);res.json({room:roomPayload(id,req.user.id)});});
app.post('/api/rooms/:id/invite',auth,(req,res)=>{const id=Number(req.params.id);const room=roomPayload(id,req.user.id);if(!room)return res.status(404).json({error:'Sala não encontrada.'});const username=String(req.body?.username||'').replace(/^@/,'');const target=db.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE').get(username);if(!target)return res.status(404).json({error:'Usuário não encontrado.'});const friendship=friendStatus(req.user.id,target.id);if(!friendship||friendship.status!=='accepted')return res.status(403).json({error:'Adicione a pessoa como amiga antes de convidá-la.'});notify(target.id,'room_invite','Convite para dublar',`@${req.user.username} convidou você para a sala ${room.code}.`,'/rooms');res.json({ok:true});});
app.patch('/api/rooms/:id/ready',auth,(req,res)=>{const id=Number(req.params.id);if(!roomPayload(id,req.user.id))return res.status(404).json({error:'Sala não encontrada.'});const characterId=Number(req.body?.character_id)||null;if(characterId){const room=db.prepare('SELECT scene_id FROM rooms WHERE id=?').get(id);if(!db.prepare('SELECT 1 FROM characters WHERE id=? AND scene_id=?').get(characterId,room.scene_id))return res.status(400).json({error:'Personagem inválido para esta cena.'});}db.prepare('UPDATE room_participants SET ready=?,character_id=? WHERE room_id=? AND user_id=?').run(req.body?.ready?1:0,characterId,id,req.user.id);res.json({room:roomPayload(id,req.user.id)});});
app.post('/api/rooms/:id/start',auth,(req,res)=>{const id=Number(req.params.id);const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(id);if(!room||room.owner_id!==req.user.id)return res.status(403).json({error:'Somente quem criou a sala pode iniciar a sessão.'});const ps=db.prepare('SELECT * FROM room_participants WHERE room_id=?').all(id);if(ps.length===0||ps.some(p=>!p.ready))return res.status(400).json({error:'Todos os participantes precisam marcar que estão prontos.'});db.prepare("UPDATE rooms SET status='recording' WHERE id=?").run(id);res.json({room:roomPayload(id,req.user.id)});});
app.post('/api/rooms/:id/close',auth,(req,res)=>{const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(Number(req.params.id));if(!room||room.owner_id!==req.user.id)return res.status(403).json({error:'Somente o organizador pode encerrar a sala.'});db.prepare("UPDATE rooms SET status='closed' WHERE id=?").run(room.id);res.json({ok:true});});

app.get('/api/scenes/:id/recordings',auth,(req,res)=>{const sceneId=Number(req.params.id);if(!canReadScene(req.user.id,sceneId))return res.status(404).json({error:'Cena não encontrada.'});const rows=db.prepare(`SELECT r.*,u.username,u.avatar,c.name AS character_name,l.text AS line_text FROM recordings r JOIN users u ON u.id=r.user_id LEFT JOIN characters c ON c.id=r.character_id JOIN lines l ON l.id=r.line_id WHERE r.scene_id=? ORDER BY r.created_at DESC`).all(sceneId);res.json({recordings:rows.map(r=>({...r,url:`/api/files/${encodeURIComponent(path.basename(r.file_path))}`}))});});
app.post('/api/scenes/:id/recordings',auth,upload.single('file'),(req,res)=>{const sceneId=Number(req.params.id);if(!req.file)return res.status(400).json({error:'Nenhuma gravação foi recebida.'});const lineId=Number(req.body?.line_id);const line=db.prepare('SELECT l.*,s.owner_id,s.visibility FROM lines l JOIN scenes s ON s.id=l.scene_id WHERE l.id=? AND l.scene_id=?').get(lineId,sceneId);const roomId=Number(req.body?.room_id)||null;const roomAccess=roomId && !!db.prepare('SELECT 1 FROM room_participants WHERE room_id=? AND user_id=?').get(roomId,req.user.id) && !!db.prepare('SELECT 1 FROM rooms WHERE id=? AND scene_id=? AND status<>\'closed\'').get(roomId,sceneId);if(!line || !(line.owner_id===req.user.id || line.visibility==='public' || roomAccess)){fs.unlinkSync(req.file.path);return res.status(403).json({error:'Você não pode enviar uma gravação para essa fala.'});}const characterId=Number(req.body?.character_id)||line.character_id;const take=db.prepare('SELECT COALESCE(MAX(take_number),0)+1 AS n FROM recordings WHERE line_id=? AND user_id=?').get(lineId,req.user.id).n;const result=db.prepare('INSERT INTO recordings (scene_id,room_id,line_id,user_id,character_id,file_path,mime_type,duration,start_offset,take_number) VALUES (?,?,?,?,?,?,?,?,?,?)').run(sceneId,roomId,lineId,req.user.id,characterId,path.basename(req.file.path),req.file.mimetype,Math.max(0,Number(req.body?.duration)||0),Math.max(0,Number(req.body?.start_offset)||line.start_time),take);const owner=line.owner_id;if(owner!==req.user.id)notify(owner,'recording','Nova tomada enviada',`@${req.user.username} enviou uma gravação.`,'/editor');res.status(201).json({recording:db.prepare('SELECT * FROM recordings WHERE id=?').get(result.lastInsertRowid)});});
app.patch('/api/recordings/:id/approve',auth,(req,res)=>{const rec=db.prepare('SELECT r.*,s.owner_id FROM recordings r JOIN scenes s ON s.id=r.scene_id WHERE r.id=?').get(Number(req.params.id));if(!rec)return res.status(404).json({error:'Tomada não encontrada.'});if(rec.owner_id!==req.user.id)return res.status(403).json({error:'Somente o editor pode aprovar uma tomada.'});db.prepare("UPDATE recordings SET status='approved' WHERE id=?").run(rec.id);db.prepare("UPDATE lines SET status='approved' WHERE id=?").run(rec.line_id);notify(rec.user_id,'recording_approved','Tomada aprovada','O editor aprovou sua gravação.','/library');res.json({ok:true});});
app.post('/api/scenes/:id/feedback',auth,(req,res)=>{const sceneId=Number(req.params.id);const scene=db.prepare('SELECT * FROM scenes WHERE id=?').get(sceneId);const roomAccess=!!db.prepare(`SELECT 1 FROM rooms r JOIN room_participants p ON p.room_id=r.id WHERE r.scene_id=? AND p.user_id=? AND r.status<>'closed'`).get(sceneId,req.user.id);if(!scene||!(scene.visibility==='public'||scene.owner_id===req.user.id||roomAccess))return res.status(404).json({error:'Cena não encontrada.'});const {line_id=null,category='other',message=''}=req.body||{};if(String(message).trim().length<5)return res.status(400).json({error:'Descreva o problema com pelo menos 5 caracteres.'});const result=db.prepare('INSERT INTO feedback (scene_id,line_id,sender_id,assignee_id,category,message) VALUES (?,?,?,?,?,?)').run(sceneId,line_id,req.user.id,scene.owner_id,String(category).slice(0,80),String(message).slice(0,3000));if(scene.owner_id!==req.user.id)notify(scene.owner_id,'feedback','Nova solicitação de correção',String(message).slice(0,140),'/feedback');res.status(201).json({feedback:db.prepare('SELECT * FROM feedback WHERE id=?').get(result.lastInsertRowid)});});
app.get('/api/feedback',auth,(req,res)=>{const rows=db.prepare(`SELECT f.*,s.title AS scene_title,l.text AS line_text, sender.username AS sender_username,assignee.username AS assignee_username FROM feedback f JOIN scenes s ON s.id=f.scene_id LEFT JOIN lines l ON l.id=f.line_id JOIN users sender ON sender.id=f.sender_id JOIN users assignee ON assignee.id=f.assignee_id WHERE f.sender_id=? OR f.assignee_id=? ORDER BY CASE f.status WHEN 'pending' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,f.created_at DESC`).all(req.user.id,req.user.id);res.json({feedback:rows});});
app.patch('/api/feedback/:id',auth,(req,res)=>{const f=db.prepare('SELECT * FROM feedback WHERE id=?').get(Number(req.params.id));if(!f)return res.status(404).json({error:'Solicitação não encontrada.'});if(f.assignee_id!==req.user.id&&f.sender_id!==req.user.id)return res.status(403).json({error:'Sem permissão.'});const status=['pending','in_progress','fixed','closed'].includes(req.body?.status)?req.body.status:f.status;const response=String(req.body?.response??f.response).slice(0,3000);db.prepare('UPDATE feedback SET status=?,response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,response,f.id);if(f.sender_id!==req.user.id)notify(f.sender_id,'feedback_reply','Sua solicitação foi atualizada',response||'O editor atualizou o status da solicitação.','/feedback');res.json({feedback:db.prepare('SELECT * FROM feedback WHERE id=?').get(f.id)});});
app.get('/api/notifications',auth,(req,res)=>{res.json({notifications:db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.user.id)});});
app.post('/api/notifications/read-all',auth,(req,res)=>{db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(req.user.id);res.json({ok:true});});

// Final MP4 export is performed with FFmpeg when it is installed and the scene has an uploaded video.
app.post('/api/scenes/:id/export',auth,requireEditor,(req,res)=>{
 const id=Number(req.params.id);const scene=db.prepare('SELECT * FROM scenes WHERE id=? AND owner_id=?').get(id,req.user.id);if(!scene)return res.status(404).json({error:'Cena não encontrada.'});if(!scene.video_path)return res.status(400).json({error:'Para exportar um MP4, envie primeiro um arquivo de vídeo autorizado. Links incorporados não são exportáveis por padrão.'});
 const video=path.join(storage,'uploads',path.basename(scene.video_path));if(!fs.existsSync(video))return res.status(400).json({error:'O arquivo de vídeo original não está disponível.'});
 const result=db.prepare("INSERT INTO exports (scene_id,user_id,status) VALUES (?,?,'queued')").run(id,req.user.id);const exportId=Number(result.lastInsertRowid);const output=path.join(storage,'uploads',`export-${exportId}-${Date.now()}.mp4`);const recs=db.prepare("SELECT r.*,l.start_time FROM recordings r JOIN lines l ON l.id=r.line_id WHERE r.scene_id=? AND (r.status='approved' OR r.id IN (SELECT MAX(r2.id) FROM recordings r2 WHERE r2.line_id=r.line_id AND r2.user_id=r.user_id)) ORDER BY r.id").all(id);
 const clipStart=Math.max(0,Number(scene.clip_start)||0);const clipEnd=Math.max(0,Number(scene.clip_end)||0);const args=['-y'];if(clipStart>0)args.push('-ss',String(clipStart));args.push('-i',video);const valid=[];for(const r of recs){const fp=path.join(storage,'uploads',path.basename(r.file_path));if(fs.existsSync(fp)){args.push('-i',fp);valid.push(r);}}
 let fc='';const mix=[];valid.forEach((r,i)=>{const input=i+1;const rawStart=Number(r.start_offset||r.start_time)||0;const delay=Math.max(0,Math.round((rawStart-clipStart)*1000));fc+=`[${input}:a]adelay=${delay}|${delay},volume=1.0[a${i}];`;mix.push(`[a${i}]`);});
 if(mix.length){if(req.body?.keep_original){fc+=`[0:a]volume=0.22[orig];${mix.join('')}[orig]amix=inputs=${mix.length+1}:duration=longest:dropout_transition=2[aout]`;}else{fc+=`${mix.join('')}amix=inputs=${mix.length}:duration=longest:dropout_transition=2[aout]`;}args.push('-filter_complex',fc,'-map','0:v:0','-map','[aout]','-c:v','libx264','-preset','veryfast','-crf','20','-pix_fmt','yuv420p','-c:a','aac');} else {args.push('-map','0:v:0');if(req.body?.keep_original)args.push('-map','0:a?','-c:a','aac');else args.push('-an');args.push('-c:v','libx264','-preset','veryfast','-crf','20','-pix_fmt','yuv420p');}
 if(clipEnd>clipStart)args.push('-t',String(clipEnd-clipStart));args.push('-movflags','+faststart',output);db.prepare("UPDATE exports SET status='processing' WHERE id=?").run(exportId);
 const child=spawn('ffmpeg',args,{stdio:'ignore'});child.on('error',err=>{db.prepare("UPDATE exports SET status='failed',error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?").run(err.code==='ENOENT'?'FFmpeg não encontrado. Instale FFmpeg e coloque-o no PATH.':err.message,exportId);});child.on('close',code=>{if(code===0&&fs.existsSync(output))db.prepare("UPDATE exports SET status='completed',file_path=?,finished_at=CURRENT_TIMESTAMP WHERE id=?").run(path.basename(output),exportId);else db.prepare("UPDATE exports SET status='failed',error='FFmpeg encerrou com erro. Verifique codecs e arquivos de áudio.',finished_at=CURRENT_TIMESTAMP WHERE id=?").run(exportId);});
 res.status(202).json({export:{id:exportId,status:'processing'},message:'A exportação começou. Você pode acompanhar o estado nesta tela.'});
});
app.get('/api/exports/:id',auth,(req,res)=>{const e=db.prepare('SELECT * FROM exports WHERE id=? AND user_id=?').get(Number(req.params.id),req.user.id);if(!e)return res.status(404).json({error:'Exportação não encontrada.'});res.json({export:{...e,downloadUrl:e.status==='completed'?`/api/exports/${e.id}/download`:null}});});
app.get('/api/exports/:id/download',auth,(req,res)=>{const e=db.prepare("SELECT * FROM exports WHERE id=? AND user_id=? AND status='completed'").get(Number(req.params.id),req.user.id);if(!e||!e.file_path)return res.status(404).json({error:'Arquivo ainda não está pronto.'});res.download(path.join(storage,'uploads',path.basename(e.file_path)),`cenasync-export-${e.id}.mp4`);});

const clientDist = path.resolve(process.cwd(), '../client/dist');
if (fs.existsSync(path.join(clientDist, 'index.html'))) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(clientDist, 'index.html')); });
}

app.use((err,req,res,_next)=>{console.error(err);if(err instanceof multer.MulterError)return res.status(err.code==='LIMIT_FILE_SIZE'?413:400).json({error:err.code==='LIMIT_FILE_SIZE'?`O arquivo ultrapassa o limite de ${MAX_UPLOAD_MB} MB.`:'Não foi possível processar o upload.'});res.status(500).json({error:err.message||'Erro interno. Tente novamente.'});});
app.listen(PORT,()=>console.log(`CenaSync API ativa em http://localhost:${PORT}`));
