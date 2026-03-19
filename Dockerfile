FROM python:3.11-slim

WORKDIR /app

# 先复制完整依赖清单，便于利用 Docker 构建缓存
COPY requirements.txt /app/requirements.txt

# 安装完整 Python 运行依赖，避免云端启动时因精简依赖缺失导致 ASGI 导入失败
RUN pip install --no-cache-dir -r /app/requirements.txt

# 复制全部项目文件入容器 (通过 .dockerignore 排除敏感与无用数据)
COPY . /app/

# 预创建运行时数据目录（Zeabur 持久化硬盘挂载点）
RUN mkdir -p /app/data

# 设置环境变量，确保 Web Server 默认监听 0.0.0.0，且容器默认走远程 API Solver
ENV HOST=0.0.0.0
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV DISABLE_SYSTEM_PROXY=true
ENV PYTHONPATH=/app

ENV SOLVER_NODES=

# 仅暴露 Web 面板端口；Turnstile 统一通过远程 API Solver 获取
EXPOSE 8000

# 直接以内联 Python 启动，避免额外入口文件未被打包时导致容器启动失败
CMD ["python", "-c", "import traceback, uvicorn; print('[startup] importing web_server...');\ntry:\n import web_server\nexcept Exception:\n print('[startup] Failed to import web_server:'); traceback.print_exc(); raise\nprint('[startup] web_server imported successfully, starting uvicorn...'); uvicorn.run(web_server.app, host='0.0.0.0', port=8000)"]
