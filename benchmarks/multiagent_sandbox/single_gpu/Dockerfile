FROM ubuntu:24.04
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv git libgomp1 libcurl4t64 ca-certificates && rm -rf /var/lib/apt/lists/*
