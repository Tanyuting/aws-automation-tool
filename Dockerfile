
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o aws-automation-tool .
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/aws-automation-tool .
COPY --from=builder /app/config/config.yaml ./config/config.yaml
# 创建非root用户
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser
USER appuser
EXPOSE 8080
CMD ["./aws-automation-tool"]
