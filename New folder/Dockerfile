FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

# Copy source files
COPY . .

# Force-create modules inside the build container
RUN rm -f go.mod go.sum
RUN go mod init myapp
RUN go get github.com/joho/godotenv
RUN go get github.com/lib/pq
RUN go mod tidy

# Build the executable
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Production Stage
FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]