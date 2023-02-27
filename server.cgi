#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const db = require('better-sqlite3')('/meta/h/habs/db/fantasy1500.db');
db.pragma('journal_mode = WAL');

const mkHash = async (pw, salt) => new Promise((res) =>
  crypto.pbkdf2(pw, salt, 10000, 256, 'sha512', (_, buf) => res(buf.toString('base64')))
);

const body = JSON.parse(fs.readFileSync(0).toString() || '{}');

console.log('access-control-allow-origin: *');
console.log('content-type: application/json\n');

let output = { status: 'failure' };

db.exec(`create table if not exists users (
  id integer primary key,
  email text not null unique,
  name text not null,
  salt text not null,
  hash text not null
)`);

db.exec(`create table if not exists picks (
  id integer primary key,
  userid integer not null unique,
  meet text not null,
  picksJson text not null,
  foreign key (userid) references users(id)
)`);

(async () => {
  switch (body.action) {
    case 'register': {
      const { email, name, password } = body;
      const salt = crypto.randomBytes(128).toString('base64');
      try {
        db.prepare(`insert into users (email, name, salt, hash) values (?, ?, ?, ?)`).run(
          email, name, salt, await mkHash(password, salt),
        );
        output = { status: 'success' };
      } catch {}
      break;
    }
    case 'getPicks': {
      const  { email, password, meet } = body;
      const { id, salt, hash } = db.prepare('select * from users where email = ?').get(email);
      if (hash === await mkHash(password, salt)) {
        const { picksJson } = db.prepare('select * from picks where userid = ? and meet = ?').get(id, meet);
        output = JSON.parse(picksJson);
      }
      break;
    }
    case 'addPicks': {
      const { email, password, meet, picksJson } = body;
      const { id, salt, hash } = db.prepare('select * from users where email = ?').get(email);
      if (hash === await mkHash(password, salt)) {
        const picks = db.prepare('select * from picks where userid = ? and meet = ?').get(id, meet);
        if (picks) {
          db.prepare('update picks set picksJson = ? where userid = ? and meet = ?').run(
            JSON.stringify(picksJson), id, meet,
          );
        } else {
          db.prepare('insert into picks (userid, meet, picksJson) values (?, ?, ?)').run(
            id, meet, JSON.stringify(picksJson)
          );
        }
        output = { status: 'success' };
      }
      break;
    }
  }
  console.log(JSON.stringify(output));
})();
