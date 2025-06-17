import { Database } from "sqlite3";
import type { Session } from "./types.ts";

let globaldb: Database | undefined = undefined;

export function dbget(query: string, params?: any[]) {
    return new Promise((resolve, reject) => {
        if (!globaldb) {
            reject("Database not initialized");
            return;
        }
        globaldb.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

export function dball(query: string, params?: any[]): Promise<any[]> {
    return new Promise((resolve, reject) => {
        if (!globaldb) {
            reject("Database not initialized");
            return;
        }
        globaldb.all(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

export function dbrun(query: string, params?: any[]) {
    return new Promise<void>((resolve, reject) => {
        if (!globaldb) {
            reject("Database not initialized");
            return;
        }
        globaldb.run(query, params, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

export async function setupdb(db: Database) {
    globaldb = db;
    await dbrun(`create table if not exists users (
        id integer primary key,
        username varchar(50) not null unique,
        password varchar(64) not null,
        email varchar(256) not null unique,
        created_at timestamp
    )`);
    await dbrun(`create table if not exists groups (
        id integer primary key,
        name varchar(50) not null,
        created_at timestamp
    )`);
    await dbrun(`create table if not exists user_groups (
        user_id int not null,
        group_id int not null,
        permissions int not null,
        joined_at timestamp,
        primary key (user_id, group_id)
    )`);
    await dbrun(`create table if not exists channels (
        id integer primary key,
        group_id int not null,
        name varchar(50) not null,
        created_at timestamp
    )`);
    await dbrun(`create table if not exists messages (
        id integer primary key,
        channel_id int not null,
        user_id int not null,
        content text not null,
        created_at timestamp
    )`);
    await dbrun(`create table if not exists lessons (
        id integer primary key,
        title varchar(100) not null,
        content text,
        created_at timestamp,
        publish_date timestamp,
        author_id int not null
    )`);
    await dbrun(`create table if not exists sessions (
        id integer primary key,
        user_id int not null,
        session_token varchar(64) not null,
        ip_address varchar(64) not null,
        created_at timestamp,
        expires_at timestamp
    )`);
}

// export async function checkSession(token: string) {
//     const record = (await dbget("SELECT * FROM `sessions` WHERE `token` = ?", [
//         token,
//     ])) as Session;
//     if (!record) return false;
//     if (record.expired_time < Date.now()) return false;
//     if (record.force_expired) return false;
//     return true;
// }