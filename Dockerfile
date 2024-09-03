FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . ./

RUN go build -o /auth-service

FROM alpine:latest

WORKDIR /

COPY --from=builder /auth-service /auth-service

EXPOSE 8081

CMD ["./auth-service"]