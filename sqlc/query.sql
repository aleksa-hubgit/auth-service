-- name: GetTokenByUsername :one
SELECT * FROM tokens
WHERE username = $1 LIMIT 1;

-- name: ListTokens :many
SELECT * FROM tokens
ORDER BY username;

-- name: CreateToken :one
INSERT INTO tokens (
  tokenString, username
) VALUES (
  $1, $2
)
RETURNING *;

-- name: UpdateToken :exec
UPDATE tokens
  set tokenString = $2,
  username = $3
WHERE id = $1;

-- name: DeleteToken :exec
DELETE FROM tokens
WHERE id = $1;