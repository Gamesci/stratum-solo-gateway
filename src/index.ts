import net from 'net';
import http from 'http';
import crypto from 'crypto';
import {
  addressToScriptPubKey, dsha256, fromLE, toLE, u64, varint
} from './utils.js';

// @ts-ignore: bcoin 没有官方 TS 类型
import bcoin from 'bcoin';
const { Block, TX, MTX, Script, Outpoint, Address } = bcoin;

/* ========== 环境变量 ========== */
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8332';
const RPC_USER = process.env.RPC_USER || 'user';
const RPC_PASS = process.env.RPC_PASS || 'pass';
const [HOST, PORT] = (process.env.LISTEN || '0.0.0.0:3333').split(':');
const PAYOUT_ADDRESS = process.env.PAYOUT_ADDRESS!;
const COINBASE_TAG = (process.env.COINBASE_TAG || '/SoloGateway/').trim();
const EXTRANONCE2_SIZE = parseInt(process.env.EXTRANONCE2_SIZE || '4', 10);
const REFRESH_MS = parseInt(process.env.REFRESH_MS || '10000', 10);
const VERSION_MASK_HEX = (process.env.VERSION_MASK || '0x1fffe000').toString().toLowerCase();
const VERSION_MASK = BigInt(VERSION_MASK_HEX);
const SHARE_DIFFICULTY = parseFloat(process.env.SHARE_DIFFICULTY || '16384'); // 可选：允许通过 env 调整 share 难度

if (!PAYOUT_ADDRESS) throw new Error('PAYOUT_ADDRESS required');

/* ========== RPC helper ========== */
function rpc<T=any>(method: string, params: any[] = []): Promise<T> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const url = new URL(RPC_URL);
    const req = http.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname || '/',
      method: 'POST',
      auth: `${RPC_USER}:${RPC_PASS}`,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject(parsed.error);
          else resolve(parsed.result);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/* ========== 类型 ========== */
type GbtTx = { data: string; txid: string };
type Gbt = {
  version: number;
  previousblockhash: string;
  transactions: GbtTx[];
  coinbasevalue: number;
  bits: string;
  curtime: number;
  height: number;
  default_witness_commitment?: string;
};

type Job = {
  jobId: string;
  coinb1: string;
  coinb2: string;
  merkleBranches: string[];
  versionHex: string;     // 模板 version（大端 8 hex）
  versionBE: number;
  prevhash: string;
  nbits: string;
  ntime: string;
  clean: boolean;
  targetHex: string;
  gbt: Gbt;
};

type ClientState = {
  id: number;
  extranonce1: Buffer;
  authorized: boolean;
  extranonceSubscribed: boolean;
  negotiatedVersionRolling: boolean;
  versionMaskHex: string; // 不带 0x 的 hex
  jobs: Map<string, Job>;
};

/* ========== 工具 ========== */
const scriptPubKey = addressToScriptPubKey(PAYOUT_ADDRESS);

function pushData(data: Buffer): Buffer {
  if (data.length < 0x4c) return Buffer.concat([Buffer.from([data.length]), data]);
  if (data.length <= 0xff) return Buffer.concat([Buffer.from([0x4c, data.length]), data]);
  if (data.length <= 0xffff) {
    const b = Buffer.allocUnsafe(2); b.writeUInt16LE(data.length, 0);
    return Buffer.concat([Buffer.from([0x4d]), b, data]);
  }
  const b = Buffer.allocUnsafe(4); b.writeUInt32LE(data.length, 0);
  return Buffer.concat([Buffer.from([0x4e]), b, data]);
}

function encodeScriptNumber(n: number): Buffer {
  const out: number[] = [];
  let x = n >>> 0;
  while (x > 0) { out.push(x & 0xff); x >>= 8; }
  if (out.length === 0) out.push(0);
  return Buffer.from(out);
}

function cryptoRandom(n: number) {
  return crypto.randomBytes(n);
}

function bitsToTargetHex(bitsHex: string) {
  const bits = Buffer.from(bitsHex, 'hex').reverse();
  const exp = bits[3];
  const mant = bits.readUInt32LE(0) & 0x00ffffff;
  const target = Buffer.alloc(32, 0);
  const mantBuf = Buffer.alloc(4);
  mantBuf.writeUInt32BE(mant, 0);
  const shift = exp - 3;
  const start = 32 - shift - 3;
  target.set(mantBuf.slice(1), start);
  return target.toString('hex');
}

function packHeader(versionHex: string, prevhashHex: string, merkleRoot: Buffer, ntimeHex: string, nbitsHex: string, nonceHex: string) {
  const verLE = Buffer.from(versionHex, 'hex').reverse();
  const prevLE = Buffer.from(prevhashHex, 'hex').reverse();
  const rootLE = Buffer.from(merkleRoot).reverse();
  const ntimeLE = Buffer.from(ntimeHex, 'hex').reverse();
  const nbitsLE = Buffer.from(nbitsHex, 'hex').reverse();
  const nonceLE = Buffer.from(nonceHex, 'hex').reverse();
  return Buffer.concat([verLE, prevLE, rootLE, ntimeLE, nbitsLE, nonceLE]);
}

function cmp256(a: Buffer, b: Buffer) { // a<=b? (big-endian)
  for (let i = 0; i < 32; i++) {
    const x = a[i], y = b[i];
    if (x < y) return true;
    if (x > y) return false;
  }
  return true;
}

async function getTemplate(): Promise<Gbt> {
  return rpc<Gbt>('getblocktemplate', [{ rules: ['segwit'] }]);
}

/* ========== 构造 Stratum 任务 ========== */
function buildJob(gbt: Gbt): Job {
  // 用标记字节划分 coinbase，便于插入 extranonce1+2
  const mark = cryptoRandom(8);
  const cbMarked = buildCoinbaseRaw(mark, gbt.height, gbt.coinbasevalue);
  const idx = cbMarked.indexOf(mark);
  if (idx < 0) throw new Error('Failed to locate extranonce splice point');
  const coinb1 = cbMarked.slice(0, idx).toString('hex');
  const coinb2 = cbMarked.slice(idx + mark.length).toString('hex');

  // Stratum merkle 分支：提供 coinbase 的兄弟路径（简化：按 tx 列表顺序折叠）
  const branches = gbt.transactions.map(t => fromLE(toLE(t.txid)));

  const prevhash = toLE(gbt.previousblockhash).toString('hex');
  const nbits = gbt.bits;
  const ntime = gbt.curtime.toString(16);
  const versionHex = gbt.version.toString(16).padStart(8, '0');

  return {
    jobId: `${gbt.height}-${Date.now().toString(16)}`,
    coinb1,
    coinb2,
    merkleBranches: branches,
    versionHex,
    versionBE: gbt.version >>> 0,
    prevhash,
    nbits,
    ntime,
    clean: true,
    targetHex: bitsToTargetHex(gbt.bits),
    gbt
  };
}

/* ========== 使用手写 coinbase 原型确定 split（bcoin 最终用于规范化区块构建） ========== */
function buildCoinbaseRaw(extra: Buffer, height: number, value: number) {
  const heightScript = encodeScriptNumber(height);
  const tag = Buffer.from(COINBASE_TAG);
  const scriptSig = Buffer.concat([
    pushData(heightScript),
    pushData(tag),
    pushData(extra)
  ]);
  const coinbaseIn = Buffer.concat([
    Buffer.alloc(32, 0),
    Buffer.alloc(4, 0xff),
    varint(scriptSig.length),
    scriptSig,
    Buffer.from('ffffffff', 'hex')
  ]);
  const outValue = u64(BigInt(value));
  const out = Buffer.concat([
    outValue,
    varint(scriptPubKey.length),
    scriptPubKey
  ]);
  return Buffer.concat([
    Buffer.from('01000000', 'hex'),
    varint(1), coinbaseIn,
    varint(1), out,
    Buffer.from('00000000', 'hex')
  ]);
}

/* ========== bcoin：构造 coinbase（含 witness 承诺）与整块 ========== */
function buildCoinbaseTX_bcoin(gbt: Gbt, extraNonce: Buffer, payoutAddr: string): TX {
  const mtx = new MTX();

  // coinbase input
  const cbScript = new Script();
  cbScript.pushInt(gbt.height);                    // BIP34 高度
  cbScript.pushData(Buffer.from(COINBASE_TAG));    // coinbase 标识
  cbScript.pushData(extraNonce);                   // extranonce1+2
  cbScript.compile();

  mtx.addInput({
    prevout: new Outpoint(Buffer.alloc(32, 0), 0xffffffff),
    script: cbScript,
    sequence: 0xffffffff
  });

  // 主输出：直付到你的地址
  const addr = Address.fromString(payoutAddr);
  mtx.addOutput({
    address: addr,
    value: gbt.coinbasevalue
  });

  // witness reserved value（32 bytes 全 0）放在 coinbase 输入的 witness[0]
  // 这用于计算默认的 witness commitment（如果模板要求）
  mtx.inputs[0].witness.push(Buffer.alloc(32, 0));

  // 如果 GBT 提供了 default_witness_commitment（一个 OP_RETURN scriptPubKey 原始 hex）
  if (gbt.default_witness_commitment) {
    const commitScript = Script.fromRaw(Buffer.from(gbt.default_witness_commitment, 'hex'));
    mtx.addOutput({
      script: commitScript,
      value: 0
    });
  }

  return mtx.toTX();
}

function buildFullBlock_bcoin(job: Job, coinbaseTx: TX, versionBE: number, ntime: number, nonceBE: number): Block {
  const block = new Block();
  block.version = versionBE >>> 0;
  block.prevBlock = Buffer.from(job.gbt.previousblockhash, 'hex').reverse();
  block.time = ntime >>> 0;
  block.bits = parseInt(job.nbits, 16) >>> 0;
  block.nonce = nonceBE >>> 0;

  // 添加交易（coinbase + GBT 给定的 mempool tx）
  block.txs.push(coinbaseTx);
  for (const tx of job.gbt.transactions) {
    block.txs.push(TX.fromRaw(Buffer.from(tx.data, 'hex')));
  }

  // 刷新计算 merkle/witness 根
  block.refresh();
  return block;
}

/* ========== 版本滚动校验（ASICBoost） ========== */
function validateRolledVersion(baseVersion: number, submittedVersion: number, mask: bigint): boolean {
  const base = BigInt(baseVersion >>> 0);
  const sub = BigInt(submittedVersion >>> 0);
  const keepMask = ~mask & 0xffffffffn;
  return ((base & keepMask) === (sub & keepMask));
}

/* ========== Stratum 连接与协议处理 ========== */
const clients = new Map<net.Socket, ClientState>();

function json(socket: net.Socket, id: any, result: any, error: any = null) {
  socket.write(JSON.stringify({ id, result, error }) + '\n');
}

function sendNotify(socket: net.Socket, job: Job) {
  const params = [
    job.jobId,
    job.prevhash,
    job.coinb1,
    job.coinb2,
    job.merkleBranches,
    job.versionHex,
    job.nbits,
    job.ntime,
    job.clean
  ];
  socket.write(JSON.stringify({ id: null, method: 'mining.notify', params }) + '\n');
  socket.write(JSON.stringify({ id: null, method: 'mining.set_difficulty', params: [SHARE_DIFFICULTY] }) + '\n');
}

function sendVersionMask(socket: net.Socket, maskHexNo0x: string) {
  socket.write(JSON.stringify({ id: null, method: 'mining.set_version_mask', params: [maskHexNo0x] }) + '\n');
}

function sendSetExtranonce(socket: net.Socket, state: ClientState) {
  socket.write(JSON.stringify({
    id: null,
    method: 'mining.set_extranonce',
    params: [state.extranonce1.toString('hex'), EXTRANONCE2_SIZE]
  }) + '\n');
}

/* ========== 区块提交 ========== */
async function submitBlock(hexBlock: string) {
  return rpc('submitblock', [hexBlock]);
}

/* ========== 主循环 ========== */
async function main() {
  let currentJob = buildJob(await getTemplate());

  // 定期刷新模板
  setInterval(async () => {
    try {
      const gbt = await getTemplate();
      if (gbt.previousblockhash !== currentJob.gbt.previousblockhash || gbt.curtime !== currentJob.gbt.curtime) {
        currentJob = buildJob(gbt);
        for (const [sock] of clients) {
          sendNotify(sock, currentJob);
        }
      }
    } catch (e) {
      console.error('GBT refresh failed:', (e as any)?.toString?.() || e);
    }
  }, REFRESH_MS);

  const server = net.createServer(socket => {
    const state: ClientState = {
      id: Math.floor(Math.random() * 1e9),
      extranonce1: cryptoRandom(4),
      authorized: false,
      extranonceSubscribed: false,
      negotiatedVersionRolling: false,
      versionMaskHex: VERSION_MASK_HEX.startsWith('0x') ? VERSION_MASK_HEX.slice(2) : VERSION_MASK_HEX,
      jobs: new Map<string, Job>([[currentJob.jobId, currentJob]])
    };
    clients.set(socket, state);

    socket.on('data', async (buf: Buffer) => {
      const lines = buf.toString().split('\n').map(s => s.trim()).filter(Boolean);
      for (const line of lines) {
        let msg: any;
        try { msg = JSON.parse(line); } catch { continue; }
        const { id, method, params } = msg;

        // 扩展：mining.configure（协商 version-rolling）
        if (method === 'mining.configure') {
          state.negotiatedVersionRolling = true;
          const result = {
            'version-rolling': true,
            'version-rolling.mask': state.versionMaskHex
          };
          json(socket, id, result);
          sendVersionMask(socket, state.versionMaskHex);
          continue;
        }

        // 扩展：mining.extranonce.subscribe
        if (method === 'mining.extranonce.subscribe') {
          state.extranonceSubscribed = true;
          json(socket, id, true);
          // 立即回发当前的 set_extranonce
          sendSetExtranonce(socket, state);
          continue;
        }

        if (method === 'mining.subscribe') {
          const extranonce1Hex = state.extranonce1.toString('hex');
          json(socket, id, [[['mining.set_difficulty', state.id], ['mining.notify', state.id]], extranonce1Hex, EXTRANONCE2_SIZE]);
          sendNotify(socket, currentJob);
          if (state.negotiatedVersionRolling) sendVersionMask(socket, state.versionMaskHex);
          if (state.extranonceSubscribed) sendSetExtranonce(socket, state);
          continue;
        }

        if (method === 'mining.authorize') {
          state.authorized = true;
          json(socket, id, true);
          continue;
        }

        if (method === 'mining.submit') {
          // [worker, job_id, extranonce2, ntime, nonce] 或 [.., version]
          const worker = params[0];
          const jobId: string = params[1];
          const en2: string = params[2];
          const ntimeHex: string = params[3];
          const nonceHex: string = params[4];
          const submittedVersionHex: string | undefined = params[5];

          const job = state.jobs.get(jobId) || currentJob;

          // coinbase = coinb1 + en1 + en2 + coinb2
          const extranonce1Hex = state.extranonce1.toString('hex');
          const coinbaseHex = job.coinb1 + extranonce1Hex + en2 + job.coinb2;
          const coinbaseBuf = Buffer.from(coinbaseHex, 'hex');

          // 计算 header 用的 merkle root
          let root = dsha256(coinbaseBuf);
          for (const branchHex of job.merkleBranches) {
            const branch = Buffer.from(branchHex, 'hex');
            root = dsha256(Buffer.concat([root, branch]));
          }

          // 处理版本滚动
          let versionHex = job.versionHex;
          let versionBE = job.versionBE;
          if (submittedVersionHex && state.negotiatedVersionRolling) {
            const subV = parseInt(submittedVersionHex, 16) >>> 0;
            const ok = validateRolledVersion(job.versionBE, subV, VERSION_MASK);
            if (!ok) {
              json(socket, id, false, { code: 22, message: 'Invalid version rolling beyond mask' });
              continue;
            }
            versionHex = subV.toString(16).padStart(8, '0');
            versionBE = subV >>> 0;
          }

          // 校验是否满足网络难度
          const header = packHeader(versionHex, job.prevhash, root, ntimeHex, job.nbits, nonceHex);
          const headerHashBE = dsha256(header);
          const targetBE = Buffer.from(job.targetHex, 'hex');
          const meets = cmp256(headerHashBE, targetBE);

          if (meets) {
            try {
              // 使用 bcoin 规范构建 coinbase（含 witness 承诺）
              const extraNonce = Buffer.from(extranonce1Hex + en2, 'hex');
              const coinbaseTX = buildCoinbaseTX_bcoin(job.gbt, extraNonce, PAYOUT_ADDRESS);

              // 用 bcoin 构建整块（自动计算 merkle/witness）
              const ntimeBE = parseInt(ntimeHex, 16) >>> 0;
              const nonceBE = parseInt(nonceHex, 16) >>> 0;
              const block = buildFullBlock_bcoin(job, coinbaseTX, versionBE, ntimeBE, nonceBE);

              // 序列化并提交
              const raw = block.toRaw();
              await submitBlock(raw.toString('hex'));
              console.log(`BLOCK FOUND by ${worker} | job=${job.jobId} | version=${versionHex}`);
            } catch (e) {
              console.error('submitblock error:', e);
            }
          }

          // solo 模式：对 submit 一律返回 true（不做 share 计分）
          json(socket, id, true);
          continue;
        }

        json(socket, id, null, { code: -3, message: 'Unknown method' });
      }
    });

    socket.on('close', () => clients.delete(socket));
    socket.on('error', () => clients.delete(socket));
  });

  server.listen(parseInt(PORT, 10), HOST, () => {
    console.log(`Stratum solo (ASICBoost + extranonce + bcoin) listening on ${HOST}:${PORT} mask=${VERSION_MASK_HEX} diff=${SHARE_DIFFICULTY}`);
  });
}

main().catch(e => { console.error(e); process.exit(1); });
