FROM ubuntu:22.04

# 1. 安装并配置SSH
RUN apt-get update && \
    apt-get install -y openssh-server sudo nano && \
    mkdir -p /var/run/sshd && \
    ssh-keygen -A && \ 
    chmod 600 /etc/ssh/ssh_host_* && \  
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 2. 设置root密码
#RUN echo 'root:pa3ss12_run_on!cewo9rd' | chpasswd

# 3. 创建普通用户并授予sudo权限
RUN useradd -m -s /bin/bash genelibs && \
    echo 'genelibs:genelibs' | chpasswd 
#    echo 'genelibs ALL=(ALL) NOPASSWD: /usr/sbin/sshd' >> /etc/sudoers

# 4. 切换用户后通过sudo启动SSH
USER root
WORKDIR /home/genelibs
EXPOSE 22

# 关键修改：使用sudo运行sshd
CMD ["/usr/sbin/sshd", "-D"]