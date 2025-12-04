#!/bin/bash
set -e
# 配置变量
APP_NAME="aws-automation-tool"
DOCKER_REGISTRY="my-registry.company.com"
ENVIRONMENT=${1:-production}
echo "开始部署 ${APP_NAME} 到 ${ENVIRONMENT} 环境"
# 检查Docker是否运行
if ! docker info > /dev/null 2>&1; then
    echo "错误: Docker守护进程未运行"
    exit 1
fi
# 拉取最新镜像
echo "拉取最新Docker镜像..."
docker pull ${DOCKER_REGISTRY}/${APP_NAME}:latest
# 停止并移除旧容器
echo "停止旧容器..."
docker-compose down
# 启动新容器
echo "启动新容器..."
docker-compose up -d
# 健康检查
echo "执行健康检查..."
sleep 30
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "部署成功: ${APP_NAME} 正在运行"
else
    echo "错误: 应用健康检查失败"
    exit 1
fi
# 清理旧镜像
echo "清理未使用的Docker镜像..."
docker image prune -f
echo "部署完成"
