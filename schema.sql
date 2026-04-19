-- VoiceCoder AI — Supabase / PostgreSQL Schema (FIXED)
-- Fix: Removed NOW() from index predicate (not allowed in PostgreSQL)

-- ─────────────────────────────────────────
--  USERS TABLE
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.users (
    id          SERIAL          PRIMARY KEY,
    name        VARCHAR(100)    NOT NULL,
    email       VARCHAR(255)    NOT NULL,
    password    VARCHAR(255)    NOT NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ     NULL,
    is_active   BOOLEAN         NOT NULL DEFAULT TRUE,

    CONSTRAINT uq_users_email UNIQUE (email)
);

-- ─────────────────────────────────────────
--  SESSIONS TABLE
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.sessions (
    id          SERIAL          PRIMARY KEY,
    user_id     INT             NOT NULL
                    REFERENCES public.users(id) ON DELETE CASCADE,
    token       VARCHAR(512)    NOT NULL,
    expires_at  TIMESTAMPTZ     NOT NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    ip_address  VARCHAR(45)     NULL,
    user_agent  VARCHAR(500)    NULL,

    CONSTRAINT uq_sessions_token UNIQUE (token)
);

-- ✅ FIXED: Removed WHERE NOW() — plain index works fine
CREATE INDEX IF NOT EXISTS ix_sessions_token
    ON public.sessions (token);

CREATE INDEX IF NOT EXISTS ix_sessions_expires_at
    ON public.sessions (expires_at);

-- ─────────────────────────────────────────
--  FUNCTIONS
-- ─────────────────────────────────────────

-- FUNCTION: Register a new user
CREATE OR REPLACE FUNCTION public.sp_create_user(
    p_name      VARCHAR(100),
    p_email     VARCHAR(255),
    p_password  VARCHAR(255)
)
RETURNS TABLE(success INT, user_id INT, error_code TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.users WHERE email = LOWER(p_email)) THEN
        RETURN QUERY SELECT 0, NULL::INT, 'EMAIL_EXISTS'::TEXT;
        RETURN;
    END IF;

    INSERT INTO public.users (name, email, password)
    VALUES (p_name, LOWER(p_email), p_password)
    RETURNING id INTO user_id;

    RETURN QUERY SELECT 1, user_id, ''::TEXT;
END;
$$;

-- FUNCTION: Fetch user by email
CREATE OR REPLACE FUNCTION public.sp_get_user_by_email(
    p_email VARCHAR(255)
)
RETURNS TABLE(id INT, name VARCHAR, email VARCHAR, password VARCHAR, is_active BOOLEAN)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.name, u.email, u.password, u.is_active
    FROM   public.users u
    WHERE  u.email = LOWER(p_email);
END;
$$;

-- FUNCTION: Update last_login timestamp
CREATE OR REPLACE FUNCTION public.sp_update_last_login(
    p_user_id INT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE public.users
    SET    last_login = NOW()
    WHERE  id = p_user_id;
END;
$$;

-- FUNCTION: Store a new session token
CREATE OR REPLACE FUNCTION public.sp_create_session(
    p_user_id    INT,
    p_token      VARCHAR(512),
    p_expires_at TIMESTAMPTZ,
    p_ip_address VARCHAR(45)  DEFAULT NULL,
    p_user_agent VARCHAR(500) DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO public.sessions (user_id, token, expires_at, ip_address, user_agent)
    VALUES (p_user_id, p_token, p_expires_at, p_ip_address, p_user_agent);
END;
$$;

-- FUNCTION: Validate a session token
CREATE OR REPLACE FUNCTION public.sp_validate_session(
    p_token VARCHAR(512)
)
RETURNS TABLE(token VARCHAR, expires_at TIMESTAMPTZ, id INT, name VARCHAR, email VARCHAR)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT s.token, s.expires_at, u.id, u.name, u.email
    FROM   public.sessions s
    JOIN   public.users    u ON u.id = s.user_id
    WHERE  s.token      = p_token
      AND  s.expires_at > NOW()
      AND  u.is_active  = TRUE;
END;
$$;

-- FUNCTION: Delete / invalidate a session (sign out)
CREATE OR REPLACE FUNCTION public.sp_delete_session(
    p_token VARCHAR(512)
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM public.sessions WHERE token = p_token;
END;
$$;

-- FUNCTION: Clean up expired sessions
CREATE OR REPLACE FUNCTION public.sp_purge_expired_sessions()
RETURNS TABLE(deleted_rows BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_count BIGINT;
BEGIN
    DELETE FROM public.sessions WHERE expires_at <= NOW();
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN QUERY SELECT v_count;
END;
$$;
