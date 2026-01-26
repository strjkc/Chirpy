-- name: RevokeToken :exec
update refresh_tokens set revoked_at = NOW() where token = $1;
