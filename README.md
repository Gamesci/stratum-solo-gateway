# Stratum Solo Gateway

一个极简的比特币 Stratum Solo 网关，直接将区块奖励支付到你的地址。

## 特性
- 纯 solo 挖矿，无 share 分配
- 直接对接 Bitcoin Core RPC
- 支持 SegWit 地址
- Docker 一键部署

## 快速开始
```bash
cp .env.example .env
docker-compose -f docker/docker-compose.yml up -d
