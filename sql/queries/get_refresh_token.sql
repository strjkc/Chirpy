-- name: GetRefreshToken :one
select token, user_id, expires_at, revoked_at from refresh_tokens where token = $1;
