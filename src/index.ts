import { Socket } from "net";
import { IncomingMessage } from "http";
import { Database } from "sqlite3";
import express from "express";
import { Request, Response } from "express";

import { setupdb, dbrun, dbget, dball } from "./db.ts";
import { sha256, createToken } from "./crypto.ts";
import { User, Session, Group } from "./types.ts"; // Assuming you have a types file for User type

import WebSocket, { WebSocketServer } from "ws";

const db = new Database("db.db");
setupdb(db);

const app = express();
const port = 3000;

app.use((req: Request, res: Response, next: express.NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

app.get("/register", async (req: Request, res: Response) => {
    // arguments : username, password, email
    const { username, password, email } = req.query;
    if (!username || !password || !email) {
        res.status(400).send(
            {
                errorCode: "missing_parameters",
                message: "Username, password, and email are required."
            }
        );
        return;
    }
    if (typeof username !== "string" || typeof password !== "string" || typeof email !== "string") {
        res.status(400).send(
            {
                errorCode: "invalid_parameters",
                message: "Username, password, and email must be strings."
            }
        );
        return;
    }
    if (username.length < 3 || username.length > 50) {
        res.status(400).send(
            {
                errorCode: "invalid_username",
                message: "Username must be between 3 and 50 characters."
            }
        );
        return;
    }
    if (password.length < 6 || password.length > 64) {
        res.status(400).send(
            {
                errorCode: "invalid_password",
                message: "Password must be between 6 and 64 characters."
            }
        );
        return;
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        res.status(400).send(
            {
                errorCode: "invalid_username_format",
                message: "Username can only contain alphanumeric characters and underscores."
            }
        );
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        res.status(400).send(
            {
                errorCode: "invalid_email_format",
                message: "Email format is invalid."
            }
        );
        return;
    }

    const hash =  sha256(password as string);
    const existingUser = await dbget(
        `SELECT * FROM users WHERE username = ? OR email = ?`,
        [username, email]
    );
    if (existingUser) {
        res.status(400).send(
            {
                errorCode: "user_exists",
                message: "Username or email already exists."
            }
        );
        return;
    }
    await dbrun(
        `INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, datetime('now'))`,
        [username, hash, email]
    );
    res.status(201).send(
        {
            success: true,
            message: "User registered successfully."
        }
    );
});

app.get("/login", async (req: Request, res: Response) => {
    // arguments : username, password
    const { username, password } = req.query;
    if (!username || !password) {
        res.status(400).send(
            {
                errorCode: "missing_parameters",
                message: "Username and password are required."
            }
        );
        return;
    }
    if (typeof username !== "string" || typeof password !== "string") {
        res.status(400).send(
            {
                errorCode: "invalid_parameters",
                message: "Username and password must be strings."
            }
        );
        return;
    }

    const hash = sha256(password as string);
    const user: User  = await dbget(
        `SELECT * FROM users WHERE (username = ? OR email = ?) AND password = ?`,
        [username, username, hash]
    ) as User;
    if (!user) {
        res.status(401).send(
            {
                errorCode: "invalid_credentials",
                message: "Invalid username or password."
            }
        );
        return;
    }

    const sessionToken = createToken();
    const session: Session = {
        id: 0, // This will be auto-incremented by SQLite
        user_id: user.id,
        session_token: sessionToken,
        ip_address: req.ip?.toString() || "unknown",
        created_at: new Date(),
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000 * 7) // 7 days expiration
    };
    await dbrun(
        `INSERT INTO sessions (user_id, session_token, ip_address, created_at, expires_at) VALUES (?, ?, ?, datetime('now'), ?)`,
        [session.user_id, session.session_token, session.ip_address, session.expires_at.toISOString()]
    );
    // Optionally, you can return the session token to the client
    res.cookie("session_token", sessionToken, { expires: new Date(Date.now() + 24 * 60 * 60 * 1000 * 7), secure: true });
    res.status(200).send(
        {
            success: true,
            message: "Login successful.",
            userId: user.id,
            sessionToken: sessionToken
        }
    );
});

const websocketServer = new WebSocketServer({ noServer: true });
websocketServer.on("connection", (ws) => {
    // console.log("New WebSocket connection established.");
    let userid: Number | undefined = undefined;
    let username: string | undefined = undefined;
    ws.on("message", async (message) => {
        let parsedMessage = JSON.parse(message.toString());
        if (!parsedMessage.opcode) {
            ws.send(JSON.stringify({ opcode: "auth_ack", success: false }));
            return;
        }
        if (userid === undefined && parsedMessage.opcode !== "auth") {
            ws.send(JSON.stringify({ opcode: "auth_ack", success: false }));
            return;
        }
        console.log(parsedMessage.opcode, "Received message:", parsedMessage);
        switch (parsedMessage.opcode) {
            case "auth":
                let token = parsedMessage.token;
                // Validate the token and authenticate the user
                const session: Session = await dbget(
                    `SELECT * FROM sessions WHERE session_token = ?`,
                    [token]
                ) as Session;
                if (!session) {
                    ws.send(JSON.stringify({ opcode: "auth_ack", success: false,  error: "Invalid session token" }));
                    ws.close();
                    return;
                }
                userid = session.user_id;
                // If valid, send a success message
                username = (await dbget(
                    `SELECT username FROM users WHERE id = ?`,
                    [userid]
                ) as User)["username"];
                ws.send(JSON.stringify({ opcode: "auth_ack", userId: session.user_id, success: true }));
                break;
            case "info":
                const userGroups = await dball(
                    `SELECT g.id, g.name, ug.permissions FROM groups g
                     JOIN user_groups ug ON g.id = ug.group_id
                     WHERE ug.user_id = ?`,
                    [userid]
                );
                const  userChannels = await dball(
                    `SELECT c.id, c.name, c.group_id FROM channels c
                     JOIN groups g ON c.group_id = g.id
                     JOIN user_groups ug ON g.id = ug.group_id
                     WHERE ug.user_id = ?`,
                    [userid]
                );
                // Send the groups to the client
                ws.send(JSON.stringify({ opcode: "info_ack", success: true, username: username, groups: userGroups,  channels: userChannels }));
                break;
            case "message":
                let content = parsedMessage.content;
                let channel_id = parsedMessage.channel_id;
                console.log(!content, !channel_id);
                if (!content || !channel_id) {
                    ws.send(JSON.stringify({ opcode: "message_ack", success: false, error: "Missing content or channel_id" }));
                    return;
                }
                if (typeof content !== "string" || typeof channel_id !== "number") {
                    ws.send(JSON.stringify({ opcode: "message_ack", success: false, error: "Invalid content or channel_id type" }));
                    return;
                }
                // Insert the message into the database
                await dbrun(
                    `INSERT INTO messages (channel_id, user_id, content, created_at) VALUES (?, ?, ?, datetime('now'))`,
                    [channel_id, userid, content]
                );
                // Acknowledge the message
                ws.send(JSON.stringify({ opcode: "message_ack", success: true }));
                // Optionally, you can broadcast the message to other connected clients
                websocketServer.clients.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN && client !== ws) {
                        client.send(JSON.stringify({
                            opcode: "new_message",
                            userId: userid,
                            channelId: channel_id,
                            content: content,
                            timestamp: new Date().toISOString()
                        }));
                    }
                });
                break;
            case "get_messages":
                let channelId = parsedMessage.channel_id;
                if (!channelId) {
                    ws.send(JSON.stringify({ opcode: "get_messages_ack", success: false, error: "Missing channel_id" }));
                    return;
                }
                if (typeof channelId !== "number") {
                    ws.send(JSON.stringify({ opcode: "get_messages_ack", success: false, error: "Invalid channel_id type" }));
                    return;
                }
                // Retrieve messages from the database
                const messages = await dball(
                    `SELECT m.id, m.content, m.created_at, u.username FROM messages m
                     JOIN users u ON m.user_id = u.id
                     WHERE m.channel_id = ?
                     ORDER BY m.created_at DESC LIMIT 10`,
                    [channelId]
                );
                // Send the messages to the client
                ws.send(JSON.stringify({ opcode: "get_messages_ack", success: true, messages: messages }));
                break;
            default:
                console.log("Unknown opcode:", parsedMessage.opcode);
                break;
        }
    });
});

async function createGroup(name: string, userId: number) {
    if (!name || typeof name !== "string") {
        throw new Error("Invalid group name");
    }
    //check if group already exists
    const existingGroup = await dbget(
        `SELECT * FROM groups WHERE name = ?`,
        [name]
    );
    if (existingGroup) {
        throw new Error("Group already exists");
    }
    // Insert the group into the database
    await dbrun(
        `INSERT INTO groups (name, created_at) VALUES (?, datetime('now'))`,
        [name]
    );
    // Get the newly created group ID
    const group: Group = await dbget(
        `SELECT * FROM groups WHERE name = ? ORDER BY id DESC LIMIT 1`,
        [name]
    ) as Group;
    if (!group) {
        throw new Error("Failed to retrieve group");
    }
    // Add the user to the group with max permissions (2^32-1)
    await dbrun(
        `INSERT INTO user_groups (user_id, group_id, permissions, joined_at) VALUES (?, ?, ?, datetime('now'))`,
        [userId, group.id, 4294967295] // Max permissions
    );
    // Return the group ID

    return group.id;
}

async function createChannel(name: string, groupId: number) {
    if (!name || typeof name !== "string") {
        throw new Error("Invalid channel name");
    }
    // Check if channel already exists in the group
    const existingChannel = await dbget(
        `SELECT * FROM channels WHERE name = ? AND group_id = ?`,
        [name, groupId]
    );
    if (existingChannel) {
        throw new Error("Channel already exists in this group");
    }
    // Insert the channel into the database
    await dbrun(
        `INSERT INTO channels (group_id, name, created_at) VALUES (?, ?, datetime('now'))`,
        [groupId, name]
    );
    // Get the newly created channel ID
    const channel = await dbget(
        `SELECT * FROM channels WHERE name = ? AND group_id = ? ORDER BY id DESC LIMIT 1`,
        [name, groupId]
    );
    if (!channel) {
        throw new Error("Failed to retrieve channel");
    }
    // Return the channel ID
    // return channel.id;
}

// async function createLesson(title: string, content: string, channelId: number, authorId: number, publishDate: Date) {

// }
// setTimeout(() => {
//     createGroup("grupa1", 1);
//     createChannel("offtop", 1);
// }, 1000);

const server = app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

server.on("upgrade", (request: IncomingMessage, socket: Socket, head: Buffer) => {
    websocketServer.handleUpgrade(request, socket, head, (ws) => {
        websocketServer.emit("connection", ws, request);
    });
});