-- name: UpdateUser :one
update users set hashed_password = $2, email = $3, updated_at = NOW() where id = $1

returning *;
