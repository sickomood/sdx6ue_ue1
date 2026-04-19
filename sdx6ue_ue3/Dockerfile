# syntax=docker/dockerfile:1.7

FROM golang:1.24.0-alpine3.21 AS builder

WORKDIR /src

COPY src/go.mod src/go.sum ./
RUN go mod download

COPY src/ ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/recipe .

FROM alpine:3.21.3

RUN addgroup -S app && adduser -S -G app app \
    && apk add --no-cache ca-certificates wget

WORKDIR /app

COPY --from=builder /out/recipe /app/recipe

USER app:app

EXPOSE 8080

ENTRYPOINT ["/app/recipe"]
CMD ["serve"]
