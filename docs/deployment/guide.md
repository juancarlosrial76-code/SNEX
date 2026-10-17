# SNEX Deployment Guide

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+)
- **CPU**: 4+ cores (8+ recommended for production)
- **RAM**: 8 GB minimum (16+ GB recommended)
- **Storage**: 50 GB SSD minimum (100+ GB recommended)
- **Network**: Static IP, TLS certificates

### Software Dependencies
- **Docker**: 24.0+
- **Docker Compose**: 2.20+
- **PostgreSQL**: 17+ (managed externally or via Docker)
- **Redis**: 7+ (managed externally or via Docker)

## Quick Start (Development)

```bash
# Clone repository
git clone https://github.com/yourorg/snex.git
cd snex

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Start infrastructure
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Run migrations
sqlx migrate run --database-url postgresql://snex:snex@localhost:5432/snex

# Build and run API
cargo run --release --bin snex-api
```

## Production Deployment

### 1. Infrastructure Setup

#### PostgreSQL (Production)
```yaml
# docker-compose.prod.yml
services:
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: snex
      POSTGRES_USER: snex
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./postgres.conf:/etc/postgresql/postgresql.conf
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U snex -d snex"]
      interval: 30s
      timeout: 10s
      retries: 3
```

#### Redis (Production)
```yaml
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### 2. Configuration

#### Environment Variables (.env.prod)
```bash
# Database
DATABASE_URL=postgresql://snex:secure_password@postgres:5432/snex
POSTGRES_PASSWORD=secure_password

# Redis
REDIS_URL=redis://:secure_redis_password@redis:6379
REDIS_PASSWORD=secure_redis_password

# Server
SNEX_SERVER__HOST=0.0.0.0
SNEX_SERVER__PORT=8080
SNEX_SERVER__WORKERS=8
SNEX_SERVER__REQUEST_TIMEOUT_SECONDS=30

# Crypto
SNEX_CRYPTO__HSM_ENABLED=true
SNEX_CRYPTO__HSM_SLOT=0
SNEX_CRYPTO__HSM_PIN=hsm_pin
SNEX_CRYPTO__BACKUP_WRAPPING_KEY_ROTATION_DAYS=7
SNEX_CRYPTO__PQ_WRAPPER_ENABLED=true

# Issuer
SNEX_ISSUER__EPOCH_DURATION_DAYS=180
SNEX_ISSUER__CREDENTIAL_LIFETIME_EPOCHS=3
SNEX_ISSUER__ADVANCE_ISSUANCE_EPOCHS=1
SNEX_ISSUER__GRACE_PERIOD_DAYS=14
SNEX_ISSUER__MINIMUM_COHORT_SIZE=30

# Verifier
SNEX_VERIFIER__MIN_BATCH_SIZE=8
SNEX_VERIFIER__MAX_BATCH_SIZE=50
SNEX_VERIFIER__BATCH_RELEASE_THRESHOLD_MIN=8
SNEX_VERIFIER__BATCH_RELEASE_THRESHOLD_MAX=12
SNEX_VERIFIER__MAX_ESTABLISHMENT_PERIOD_HOURS=72
SNEX_VERIFIER__MINIMUM_ANONYMITY_SET=30

# Anchoring
SNEX_ANCHORING__ANCHOR_INTERVAL_SECONDS=3600
SNEX_ANCHORING__MAX_ANCHOR_GAP_SECONDS=259200
SNEX_ANCHORING__ANCHOR_SERVICES=["https://tsa.example.com"]
SNEX_ANCHORING__WITNESS_ENABLED=true
SNEX_ANCHORING__WITNESS_ENDPOINTS=["https://witness1.example.com", "https://witness2.example.com"]

# Retention
SNEX_RETENTION__REGIME1_GENERATIONS=14
SNEX_RETENTION__REGIME1_GENERATION_INTERVAL_HOURS=24
SNEX_RETENTION__REGIME2_GENERATIONS=8
SNEX_RETENTION__REGIME2_GENERATION_INTERVAL_HOURS=168

# Logging
SNEX_LOGGING__LEVEL=info
SNEX_LOGGING__FORMAT=json
SNEX_LOGGING__JSON_OUTPUT=true
SNEX_LOGGING__LOG_SQL=false
```

### 3. HSM Setup

#### SoftHSM2 (Development/Testing)
```bash
# Install SoftHSM2
apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "SNEX HSM" --pin 1234 --so-pin 5678

# Configure PKCS#11
cat > /etc/softhsm2.conf <<EOF
directories.tokendir = /var/lib/softhsm/tokens/
objectstore.backend = file
log.level = INFO
EOF

# Set environment
export SOFTHSM2_CONF=/etc/softhsm2.conf
```

#### Production HSM (Thales nShield, AWS CloudHSM, Azure Dedicated HSM)
```bash
# Configure PKCS#11 library path
export SNEX_CRYPTO__HSM_LIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so
export SNEX_CRYPTO__HSM_SLOT=0
export SNEX_CRYPTO__HSM_PIN=user_pin
```

### 4. TLS Certificates

#### Using Let's Encrypt (Certbot)
```bash
# Install certbot
apt-get install certbot

# Obtain certificates
certbot certonly --standalone -d api.snex.example.com

# Configure auto-renewal
echo "0 0 * * * root certbot renew --quiet" > /etc/cron.d/certbot-renew
```

#### Certificate Paths
```bash
# In .env
SNEX_SERVER__TLS_CERT_PATH=/etc/letsencrypt/live/api.snex.example.com/fullchain.pem
SNEX_SERVER__TLS_KEY_PATH=/etc/letsencrypt/live/api.snex.example.com/privkey.pem
```

### 5. Build and Deploy

#### Build Images
```bash
# Build all images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Or build individually
docker build -f Dockerfile.api -t snex-api:latest .
docker build -f Dockerfile.issuer -t snex-issuer:latest .
docker build -f Dockerfile.verifier -t snex-verifier:latest .
docker build -f Dockerfile.registry -t snex-registry:latest .
docker build -f Dockerfile.anchoring -t snex-anchoring:latest .
docker build -f Dockerfile.retention -t snex-retention:latest .
```

#### Deploy
```bash
# Start all services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check status
docker-compose -f docker-compose.yml -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.yml -f docker-compose.prod.yml logs -f
```

### 6. Database Migrations

```bash
# Run migrations
docker run --rm --network snex-network \
  -e DATABASE_URL=postgresql://snex:password@postgres:5432/snex \
  snex-api:latest sqlx migrate run

# Or using sqlx-cli
sqlx migrate run --database-url $DATABASE_URL
```

### 7. Health Checks

```bash
# Check API health
curl -f http://localhost:8080/health

# Check all services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml ps

# Check individual service logs
docker-compose logs snex-api
docker-compose logs snex-issuer
docker-compose logs snex-verifier
```

## Monitoring

### Prometheus Metrics
```yaml
# Add to docker-compose.prod.yml
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
```

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'snex'
    static_configs:
      - targets: ['snex-api:8080', 'snex-issuer:9090', 'snex-verifier:9090', 'snex-registry:9090']
```

### Grafana Dashboards
Import SNEX dashboards from `docs/deployment/grafana-dashboards/`

### Log Aggregation
```yaml
# Loki + Promtail
  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"
    volumes:
      - ./loki-config.yml:/etc/loki/local-config.yaml

  promtail:
    image: grafana/promtail:latest
    volumes:
      - /var/log:/var/log
      - ./promtail-config.yml:/etc/promtail/config.yml
```

## Backup and Recovery

### Automated Backups
```bash
# Daily database backup
pg_dump -h postgres -U snex snex | gzip > /backups/snex-$(date +%F).sql.gz

# Weekly Redis backup
redis-cli -a $REDIS_PASSWORD BGSAVE
cp /data/dump.rdb /backups/redis-$(date +%F).rdb
```

### Recovery Procedure
```bash
# Restore database
gunzip -c /backups/snex-2026-01-15.sql.gz | psql -h postgres -U snex snex

# Restore Redis
redis-cli -a $REDIS_PASSWORD SHUTDOWN NOSAVE
cp /backups/redis-2026-01-15.rdb /data/dump.rdb
docker restart snex-redis
```

## Scaling

### Horizontal Scaling
```yaml
# Increase API replicas
deploy:
  replicas: 3
```

### Database Read Replicas
```yaml
# Add read replica
  postgres-replica:
    image: postgres:17-alpine
    environment:
      POSTGRES_MASTER_SERVICE: postgres
    command: postgres -c hot_standby=on
```

### Redis Cluster
```yaml
# Redis Cluster mode
  redis-cluster:
    image: redis:7-alpine
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf
```

## Security Hardening

### Network
- Use Docker networks with internal communication only
- Expose only API gateway on public interface
- Use TLS for all inter-service communication

### Access Control
- Rotate HSM pins regularly
- Use separate service accounts
- Enable audit logging

### Updates
```bash
# Weekly security updates
apt-get update && apt-get upgrade -y

# Rebuild images monthly
docker-compose build --no-cache
docker-compose up -d
```

## Troubleshooting

### Common Issues

#### Database Connection Failed
```bash
# Check PostgreSQL logs
docker logs snex-postgres

# Verify connection
psql -h localhost -U snex -d snex -c "SELECT 1"
```

#### Redis Connection Failed
```bash
# Check Redis logs
docker logs snex-redis

# Verify connection
redis-cli -a $REDIS_PASSWORD ping
```

#### HSM Not Available
```bash
# Check SoftHSM
softhsm2-util --show-slots

# Check PKCS#11 library
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L
```

#### Epoch Not Rotating
```bash
# Check issuer logs
docker logs snex-issuer | grep epoch

# Manual epoch rotation
curl -X POST http://localhost:8080/api/issuer/cohort/close
```

## Rollback Procedure

```bash
# Stop services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml down

# Restore database backup
gunzip -c /backups/snex-2026-01-15.sql.gz | psql -h postgres -U snex snex

# Deploy previous image tags
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d \
  snex-api:v1.0.0 snex-issuer:v1.0.0 snex-verifier:v1.0.0

# Verify
curl -f http://localhost:8080/health
```

## Maintenance Windows

- **Weekly**: Security updates, log rotation
- **Monthly**: Dependency updates, image rebuilds
- **Quarterly**: HSM key rotation, certificate renewal
- **Annually**: Disaster recovery drill