# 使用官方 Go 作为构建阶段的基础镜像
FROM golang:1.23 AS builder

# 设置工作目录
WORKDIR /app

# 复制代码并编译
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o dns-sub-prometheus

# 运行容器的最终镜像
FROM alpine:latest

# 安装 libc6-compat 以提供基本的 C 运行库支持（如果需要）
RUN apk add --no-cache libc6-compat

# 设置工作目录
WORKDIR /root/

# 复制编译好的二进制文件
COPY --from=builder /app/dns-sub-prometheus /bin/dns-sub-prometheus

# 确保二进制文件可执行
RUN chmod +x /bin/dns-sub-prometheus

# 运行应用
ENTRYPOINT ["/bin/dns-sub-prometheus"]
