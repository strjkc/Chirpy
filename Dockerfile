FROM golang:1.25.7
WORKDIR /app
RUN go install github.com/pressly/goose/v3/cmd/goose@latest
COPY go.mod go.sum ./
COPY *.go ./
COPY assets ./assets
COPY internal ./internal
COPY sql ./sql
COPY sqlc.yaml ./sqlc.yaml
COPY users ./users
RUN go build -o server .
EXPOSE 8080
