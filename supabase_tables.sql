-- Run this in Supabase → SQL Editor

-- 1. Cloud files table
CREATE TABLE IF NOT EXISTS public.user_files (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  filename   TEXT NOT NULL,
  code       TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, filename)
);

-- 2. Shared files table
CREATE TABLE IF NOT EXISTS public.shared_files (
  id         SERIAL PRIMARY KEY,
  share_id   TEXT NOT NULL UNIQUE,
  filename   TEXT NOT NULL DEFAULT 'snippet.cpp',
  code       TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. AI chat history table  
CREATE TABLE IF NOT EXISTS public.chat_history (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  history    TEXT NOT NULL DEFAULT '[]',
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
