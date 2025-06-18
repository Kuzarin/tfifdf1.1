# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.18 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app

# Run stage
FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/app /app/app
COPY --from=builder /app/main.go /app/main.go
EXPOSE 8080
CMD ["/app/app"] 