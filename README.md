# 🚀 Solo Bitcoin Mining Gateway

一个基于 Node.js 的 **比特币 Solo 挖矿网关**，支持通过 Stratum 协议连接矿机，直接对接 Bitcoin Core 节点（或兼容节点），在找到区块后将奖励直接打到指定钱包地址。

## ✨ 功能特性
- 支持 **Stratum TCP** 协议，兼容常见矿机
- 直接连接 **Bitcoin Core / btcd / bcoin** 等全节点
- 使用 **getblocktemplate** 获取挖矿任务
- 使用 **submitblock** 提交完整区块
- **ZMQ 实时监听** 新区块，自动刷新任务
- 支持自定义 `EXTRANONCE2_SIZE`、难度、奖励地址
- Docker 一键部署，支持多平台构建

## 📦 环境依赖
- Node.js >= 18
- Bitcoin Core >= v24.0（建议 v29.0）
- 已开启 RPC 和 ZMQ 推送的全节点
- 矿机支持 Stratum 协议

## ⚙️ 配置
在项目根目录创建 `.env` 文件：
```env
RPC_URL=http://127.0.0.1:8332
RPC_USER=你的RPC用户名
RPC_PASS=你的RPC密码
ZMQ_BLOCK=tcp://127.0.0.1:28332
PAYOUT_ADDRESS=你的BTC收款地址
EXTRANONCE2_SIZE=4
SHARE_DIFFICULTY=16384
LISTEN_PORT=3333
Bitcoin Core 节点配置示例（bitcoin.conf）：

conf
server=1
rpcuser=你的RPC用户名
rpcpassword=你的RPC密码
rpcallowip=你的网关IP
zmqpubhashblock=tcp://0.0.0.0:28332
txindex=1
🚀 启动
本地运行
bash
npm install
npm run build
npm start
Docker 运行
bash
docker build -t solo-gateway .
docker run -d --name solo-gateway --network host --env-file .env solo-gateway
🛠 工作原理
网关通过 RPC 调用 getblocktemplate 获取挖矿任务

将任务转换为 Stratum 协议格式下发给矿机

矿机提交的 share 如果满足全网难度 → 构造完整区块 → 调用 submitblock 提交到节点

奖励直接打到 PAYOUT_ADDRESS

通过 ZMQ 监听新区块，自动刷新任务

📜 License
本项目采用 MIT License 开源协议
