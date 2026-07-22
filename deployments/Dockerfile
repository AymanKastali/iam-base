# deployments/Dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

FROM alpine:3.20
RUN adduser -D -H iam
COPY --from=builder /out/server /usr/local/bin/server
USER iam
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
