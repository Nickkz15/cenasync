import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const storage = path.resolve(here, '../storage');
fs.mkdirSync(path.join(storage, 'uploads'), { recursive: true });
const db = new Database(path.join(storage, 'cenasync.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
 avatar TEXT NOT NULL DEFAULT '🎙️', editor_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS friendships (
 id INTEGER PRIMARY KEY AUTOINCREMENT, requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(requester_id, recipient_id), CHECK(requester_id <> recipient_id)
);
CREATE TABLE IF NOT EXISTS scenes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', source_type TEXT NOT NULL DEFAULT 'upload',
 source_url TEXT NOT NULL DEFAULT '', source_label TEXT NOT NULL DEFAULT 'Arquivo enviado', video_path TEXT,
 cover_path TEXT, duration REAL NOT NULL DEFAULT 0, clip_start REAL NOT NULL DEFAULT 0, clip_end REAL NOT NULL DEFAULT 0, language TEXT NOT NULL DEFAULT 'pt-BR',
 dub_language TEXT NOT NULL DEFAULT 'pt-BR', suggested_cast INTEGER NOT NULL DEFAULT 2,
 status TEXT NOT NULL DEFAULT 'draft', visibility TEXT NOT NULL DEFAULT 'private',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scene_versions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 version_number INTEGER NOT NULL, label TEXT NOT NULL DEFAULT '', snapshot_json TEXT NOT NULL,
 created_by INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(scene_id, version_number)
);
CREATE TABLE IF NOT EXISTS characters (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 name TEXT NOT NULL, color TEXT NOT NULL DEFAULT '#f05b80', avatar TEXT NOT NULL DEFAULT '🎭',
 description TEXT NOT NULL DEFAULT '', direction TEXT NOT NULL DEFAULT '', sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS lines (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 character_id INTEGER REFERENCES characters(id) ON DELETE SET NULL, text TEXT NOT NULL DEFAULT '',
 start_time REAL NOT NULL DEFAULT 0, end_time REAL NOT NULL DEFAULT 2,
 direction TEXT NOT NULL DEFAULT '', emotion TEXT NOT NULL DEFAULT 'Neutro',
 pronunciation TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rooms (
 id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL UNIQUE, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 scene_id INTEGER REFERENCES scenes(id) ON DELETE SET NULL, title TEXT NOT NULL DEFAULT 'Sessão de dublagem',
 status TEXT NOT NULL DEFAULT 'lobby', current_line_id INTEGER REFERENCES lines(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS room_participants (
 id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, character_id INTEGER REFERENCES characters(id) ON DELETE SET NULL,
 ready INTEGER NOT NULL DEFAULT 0, joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(room_id, user_id)
);
CREATE TABLE IF NOT EXISTS recordings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL, line_id INTEGER NOT NULL REFERENCES lines(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, character_id INTEGER REFERENCES characters(id) ON DELETE SET NULL,
 file_path TEXT NOT NULL, mime_type TEXT NOT NULL DEFAULT 'audio/webm', duration REAL NOT NULL DEFAULT 0,
 start_offset REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'submitted', take_number INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS feedback (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 line_id INTEGER REFERENCES lines(id) ON DELETE SET NULL, sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 assignee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, category TEXT NOT NULL DEFAULT 'other',
 message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', response TEXT NOT NULL DEFAULT '',
 version_label TEXT NOT NULL DEFAULT 'v1', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 type TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',
 is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS favorites (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, scene_id)
);
CREATE TABLE IF NOT EXISTS exports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scene_id INTEGER NOT NULL REFERENCES scenes(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'queued', file_path TEXT, error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS editor_access_attempts (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, ip TEXT NOT NULL,
 failures INTEGER NOT NULL DEFAULT 0, window_started INTEGER NOT NULL DEFAULT 0, blocked_until INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(user_id, ip)
);
CREATE TABLE IF NOT EXISTS editor_ip_attempts (
 ip TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, window_started INTEGER NOT NULL DEFAULT 0, blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS room_messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, message TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS room_invites (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
 sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_room_invites_pending ON room_invites(room_id,recipient_id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS room_progress (
 room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 line_id INTEGER REFERENCES lines(id) ON DELETE SET NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(room_id,user_id)
);
CREATE INDEX IF NOT EXISTS idx_scenes_owner ON scenes(owner_id);
CREATE INDEX IF NOT EXISTS idx_scene_versions_scene ON scene_versions(scene_id, version_number DESC);
CREATE INDEX IF NOT EXISTS idx_lines_scene ON lines(scene_id, sort_order, start_time);
CREATE INDEX IF NOT EXISTS idx_recordings_line ON recordings(line_id, created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at);
`);
// Lightweight migrations for databases created by earlier CenaSync builds.
try { db.exec('ALTER TABLE scenes ADD COLUMN clip_start REAL NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE scenes ADD COLUMN clip_end REAL NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE room_participants ADD COLUMN finished_at TEXT'); } catch {}
try { db.exec('ALTER TABLE exports ADD COLUMN room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL'); } catch {}
export { db, storage };
