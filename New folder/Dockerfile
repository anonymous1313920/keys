# Build phase
FROM golang:1.22-alpine AS builder
WORKDIR /app

# Copy module files first
COPY go.mod ./
COPY go.sum* ./

# Download dependencies (or generate missing locks)
RUN go mod download

# Copy source code and compile
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Run phase
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]