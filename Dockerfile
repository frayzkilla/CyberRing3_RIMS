FROM golang:1.20 as builder
LABEL stage=builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./
RUN CGO_ENABLED=1 go build -o app cmd/app/main.go

FROM debian:bookworm-slim

WORKDIR /app

# wget is required for the container HEALTHCHECK (see docker-compose.yml)
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/app .
COPY .env .
RUN mkdir ./jwt_secret && touch ./jwt_secret/secret
RUN mkdir /database
