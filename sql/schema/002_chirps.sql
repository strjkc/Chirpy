-- +goose Up
CREATE TABLE chirps(
  id UUID PRIMARY KEY,
  created_at TIMESTAMP NOT NULL,
  updated_at timestamp not null,
  body TEXT not null,
  user_id uuid not null REFERENCES users(id) on delete cascade);

-- +goose Down
DROP TABLE chirps;

