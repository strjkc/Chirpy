-- name: SetChirpyRed :execresult
update users set is_chirpy_red = TRUE where id = $1;

