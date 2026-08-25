# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git (required for downloading dependencies)
RUN apk add --no-cache git

# Copy dependency definition files
COPY go.mod go.sum ./

# Download modules before building
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the executable
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Stage 2: Create lightweight running container
FROM alpine:latest

WORKDIR /app

# Install CA certificates for secure HTTPS database connections
RUN apk add --no-cache ca-certificates

# Copy compiled binary from builder
COPY --from=builder /app/main .

EXPOSE 8080

CMD ["./main"]