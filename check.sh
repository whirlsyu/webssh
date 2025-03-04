#!/bin/bash

# 检查Docker容器SSH连通性
# 用法：./check_docker_ssh.sh [容器名称/ID] [SSH端口(可选，默认22)]

CONTAINER_NAME=$1
SSH_PORT=${2:-22}

# 验证输入参数
if [ -z "$CONTAINER_NAME" ]; then
    echo "错误：必须指定容器名称或ID"
    echo "用法：$0 [容器名称/ID] [SSH端口(可选)]"
    exit 1
fi

# 检查容器是否存在
if ! docker inspect "$CONTAINER_NAME" &> /dev/null; then
    echo "错误：容器 $CONTAINER_NAME 不存在或未运行"
    exit 2
fi

# 获取网络信息
NETWORK_MODE=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CONTAINER_NAME")
HOST_IP=$(docker inspect -f '{{.NetworkSettings.Ports}}' "$CONTAINER_NAME" | grep -oP '0.0.0.0:\K\d+')

# 获取实际检测目标
if [ "$NETWORK_MODE" == "host" ]; then
    TARGET_IP="127.0.0.1"
    TARGET_PORT=$SSH_PORT
    echo "检测模式：Host网络模式"
else
    MAPPED_PORT=$(docker port "$CONTAINER_NAME" "$SSH_PORT" 2>/dev/null | cut -d':' -f2)
    if [ -n "$MAPPED_PORT" ]; then
        TARGET_IP="127.0.0.1"
        TARGET_PORT=$MAPPED_PORT
        echo "检测模式：端口映射模式"
    else
        TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME")
        TARGET_PORT=$SSH_PORT
        echo "检测模式：容器直接访问"
    fi
fi

# 执行端口检测
echo "正在检测目标：$TARGET_IP:$TARGET_PORT"
if nc -zv -w 3 "$TARGET_IP" "$TARGET_PORT" &> /dev/null; then
    echo "✅ 端口 $TARGET_PORT 已开放"
    
    # 执行SSH协议握手检测
    if echo "SSH-2.0-OpenSSH_8.9p1" | nc -w 3 "$TARGET_IP" "$TARGET_PORT" | grep -q "SSH-2.0"; then
        echo "✅ 检测到SSH服务响应"
        
        # 执行快速连接测试
        if ssh -o StrictHostKeyChecking=no \
               -o UserKnownHostsFile=/dev/null \
               -o PasswordAuthentication=no \
               -o ConnectTimeout=3 \
               -p "$TARGET_PORT" \
               "testuser@$TARGET_IP" exit &> /dev/null; then
            echo "✅ SSH连接测试成功"
        else
            echo "⚠️  SSH服务响应正常，但连接失败"
            echo "    可能需要检查以下配置："
            echo "    - 容器SSH服务配置(/etc/ssh/sshd_config)"
            echo "    - 用户认证方式(密钥/密码)"
        fi
    else
        echo "❌ 端口开放但未检测到SSH协议响应"
        echo "    可能原因："
        echo "    1. 容器未运行SSH服务"
        echo "    2. 服务监听了其他端口"
        echo "    3. 存在网络过滤规则"
    fi
else
    echo "❌ 端口 $TARGET_PORT 不可达"
    echo "    可能原因："
    echo "    1. 容器未暴露SSH端口"
    echo "    2. 防火墙/安全组限制"
    echo "    3. SSH服务未运行"
fi