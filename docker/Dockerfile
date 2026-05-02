FROM golang:1.22-alpine AS builder

WORKDIR /app
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o analyzer cmd/main.go

FROM alpine:latest
RUN apk add --no-cache sqlite-libs ca-certificates

WORKDIR /app
COPY --from=builder /app/analyzer .
COPY configs/config.env.example configs/config.env

RUN mkdir -p data/output

VOLUME ["/app/data"]

CMD ["./analyzer"]
