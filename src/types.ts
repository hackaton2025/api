// TypeScript types generated from bazy.sql

export type User = {
  id: number;
  username: string;
  password: string;
  email: string;
  created_at: Date; // timestamp
};

export type Group = {
  id: number;
  name: string;
  created_at: Date; // timestamp
};

export type UserGroup = {
  user_id: number;
  group_id: number;
  permissions: number;
  joined_at: Date; // timestamp
};

export type Channel = {
  id: number;
  group_id: number;
  name: string;
  created_at: Date; // timestamp
};

export type Message = {
  id: number;
  channel_id: number;
  user_id: number;
  content: string;
  created_at: Date; // timestamp
};

export type Lesson = {
  id: number;
  title: string;
  content: string;
  channel_id: number;
  created_at: Date; // timestamp
  publish_date: Date; // timestamp
  author_id: number;
};

export type Session = {
  id: number;
  user_id: number;
  session_token: string;
  ip_address: string;
  created_at: Date; // timestamp
  expires_at: Date; // timestamp
};
