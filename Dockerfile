FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

WORKDIR /app

# 仅在依赖变更时重建该层
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# 一键启动：先在事务内完成 SQLite 建表与复核指纹迁移（幂等，可重复执行），
# 依赖已在构建期安装；初始化成功后再启动对外服务。
CMD ["sh", "-c", "python -c 'from app import database; database.init_db()' && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
