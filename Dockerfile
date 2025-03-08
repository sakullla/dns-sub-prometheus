# 使用官方 Go 作为基础镜像
FROM golang:1.23 AS builder

# 设置工作目录
WORKDIR /app

# 复制代码并编译
COPY . .
RUN go mod tidy && go build -o dns-sub-prometheus

# 运行容器的最终镜像
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/dns-sub-prometheus .

# 运行应用
CMD ["./dns-sub-prometheus"]
