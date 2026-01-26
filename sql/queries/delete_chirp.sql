-- name: DeleteChirp :execresult
delete from chirps where id = $1 and user_id = $2;
