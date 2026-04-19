-- Run this in your Supabase SQL Editor

-- Cloud file storage
CREATE TABLE IF NOT EXISTS public.user_files (
    id          SERIAL       PRIMARY KEY,
    user_id     INT          NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    filename    VARCHAR(255) NOT NULL,
    code        TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_files UNIQUE (user_id, filename)
);
CREATE INDEX IF NOT EXISTS ix_user_files_user_id ON public.user_files (user_id);

-- Shared code snippets (no auth required)
CREATE TABLE IF NOT EXISTS public.shared_files (
    id          SERIAL       PRIMARY KEY,
    share_id    VARCHAR(32)  NOT NULL UNIQUE,
    filename    VARCHAR(255) NOT NULL,
    code        TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_shared_files_share_id ON public.shared_files (share_id);

-- AI chat history per user
CREATE TABLE IF NOT EXISTS public.chat_history (
    id          SERIAL       PRIMARY KEY,
    user_id     INT          NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
    history     TEXT         NOT NULL DEFAULT '[]',
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
