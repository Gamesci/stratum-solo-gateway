import net from 'net';
import http from 'http';
import https from 'https';
import crypto from 'crypto';
import zmq from 'zeromq';
import {
  addressToScriptPubKey, dsha256, toLE, u64, varint,
  merkleBranchesForCoinbaseAt0
} from './utils.js';

// @ts-ignore: bcoin 无官方 TS 类型
import bcoin from 'bcoin';
const { Block, TX, MTX, Script, Outpoint, Address } = bcoin;
type TXType = InstanceType<typeof TX>;
type BlockType = InstanceType<typeof Block>;

/* ===== Env ===== */
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
const SHARE_DIFFICULTY = parseFloat(process.env.SHARE_DIFFICULTY || '16384');
const ZMQ_BLOCK = process.env.ZMQ_BLOCK || 'tcp://bitcoin:28332';
if (!PAYOUT_ADDRESS) throw new Error('PAYOUT_ADDRESS required');

/* ===== Local RPC helper + retry ===== */
function rawRpc<T=any>(method: string, params: any[] = []): Promise<T> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const url = new URL(RPC_URL);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const req = client.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname || '/',
      method: 'POST',
      auth: `${RPC_USER}:${RPC_PASS}`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Connection': 'close'
      },
      timeout: 30000
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject(parsed.error);
          else resolve(parsed.result);
        } catch (e) {
          console.error('RPC response parse error:', e, 'Data:', data);
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('RPC request timeout'));
    });

    req.write(body);
    req.end();
  });
}

async function rpc<T=any>(method: string, params: any[] = [], retries = 3): Promise<T> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await rawRpc<T>(method, params);
    } catch (e) {
      if (attempt === retries) throw e;
      const backoffMs = 500 * attempt;
      console.warn(`RPC ${method} failed (attempt ${attempt}), retrying in ${backoffMs}ms...`);
      await new Promise(r => setTimeout(r, backoffMs));
    }
  }
  throw new Error('unreachable');
}

/* ===== Types ===== */
type GbtTx = { data: string; txid: string; hash?: string };
type Gbt = {
  version: number;
  previousblockhash: string;
  transactions: GbtTx[];
  coinbasevalue: number;
  bits: string;
  curtime: number;
  height: number;
  mutable?: string[];
  target?: string;
  rules?: string[];
  default_witness_commitment?: string;
  weightlimit?: number;
};
type Job = {
  jobId: string;
  coinb1: string;
  coinb2: string;
  merkleBranchesLE: string[];
  versionHex: string;
  versionBE: number;
  prevhashLE: string;
  prevhashBE: string;
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
  versionMaskHex: string;
  jobs: Map<string, Job>;
};

/* ===== Helpers ===== */
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
  if (out[out.length - 1] & 0x80) out.push(0);
  return Buffer.from(out);
}

function cryptoRandom(n: number) { return crypto.randomBytes(n); }

// 标准 compact bits → target（与 Bitcoin Core 一致）
function bitsToTargetHex(bitsHex: string) {
  const bits = Buffer.from(bitsHex, 'hex');
  const exp = bits.readUInt8(0);
  const mant = bits.readUIntBE(1, 3);
  const shift = 8n * (BigInt(exp) - 3n);
  let target = BigInt(mant);
  if (shift > 0) target = target << shift;
  return target.toString(16).padStart(64, '0');
}

function packHeader(versionHex: string, prevhashBE: string, merkleRoot: Buffer, ntimeHex8: string, nbitsHex: string, nonceHex8: string) {
  const verLE = Buffer.from(versionHex, 'hex').reverse();
  const prevLE = Buffer.from(prevhashBE, 'hex').reverse();
  const rootLE = Buffer.from(merkleRoot).reverse();
  const ntimeLE = Buffer.from(ntimeHex8, 'hex').reverse();
  const nbitsLE = Buffer.from(nbitsHex, 'hex').reverse();
  const nonceLE = Buffer.from(nonceHex8, 'hex').reverse();
  return Buffer.concat([verLE, prevLE, rootLE, ntimeLE, nbitsLE, nonceLE]);
}

function cmp256(a: Buffer, b: Buffer) {
  for (let i = 0; i < 32; i++) {
    const x = a[i], y = b[i];
    if (x < y) return true;
    if (x > y) return false;
  }
  return true;
}

async function getTemplate(): Promise<Gbt> {
  return rpc<Gbt>('getblocktemplate', [{ rules: ['segwit'] }], 3);
}

/* ===== Job builder ===== */
function buildJob(gbt: Gbt): Job {
  const mark = cryptoRandom(8);
  const cbMarked = buildCoinbaseRaw(mark, gbt.height, gbt.coinbasevalue);
  const idx = cbMarked.indexOf(mark);
  if (idx < 0) throw new Error('Failed to locate extranonce splice point');
  const coinb1 = cbMarked.slice(0, idx).toString('hex');
  const coinb2 = cbMarked.slice(idx + mark.length).toString('hex');

  const nonCbTxidsBE = gbt.transactions
    .map(t => t.txid || t.hash)
    .filter((x): x is string => !!x);

  const merkleBranchesLE = merkleBranchesForCoinbaseAt0(nonCbTxidsBE);

  const prevhashBE = gbt.previousblockhash;
  const prevhashLE = toLE(prevhashBE).toString('hex');

  const nbits = gbt.bits;
  const ntime = gbt.curtime.toString(16).padStart(8, '0');
  const versionHex = gbt.version.toString(16).padStart(8, '0');

  return {
    jobId: `${gbt.height}-${Date.now().toString(16)}`,
    coinb1,
    coinb2,
    merkleBranchesLE,
    versionHex,
    versionBE: gbt.version >>> 0,
    prevhashLE,
    prevhashBE,
    nbits,
    ntime,
    clean: true,
    targetHex: bitsToTargetHex(gbt.bits),
    gbt
  };
}

function buildCoinbaseRaw(extra: Buffer, height: number, value: number) {
  const heightScript = encodeScriptNumber(height);
  const tag = Buffer.from(COINBASE_TAG);
  const scriptSig = Buffer.concat([pushData(heightScript), pushData(tag), pushData(extra)]);
  const coinbaseIn = Buffer.concat([
    Buffer.alloc(32, 0),
    Buffer.alloc(4, 0xff),
    varint(scriptSig.length),
    scriptSig,
    Buffer.from('ffffffff', 'hex')
  ]);
  const outValue = u64(BigInt(value));
  const out = Buffer.concat([outValue, varint(scriptPubKey.length), scriptPubKey]);
  return Buffer.concat([
    Buffer.from('01000000', 'hex'),
    varint(1), coinbaseIn,
    varint(1), out,
    Buffer.from('00000000', 'hex')
  ]);
}

/* ===== bcoin: coinbase + full block ===== */
function buildCoinbaseTX_bcoin(gbt: Gbt, extraNonce: Buffer, payoutAddr: string): TXType {
  const mtx = new MTX();

  const cbScript = new Script();
  cbScript.pushData(encodeScriptNumber(gbt.height));
  cbScript.pushData(Buffer.from(COINBASE_TAG));
  cbScript.pushData(extraNonce);
  cbScript.compile();

  mtx.addInput({
    prevout: new Outpoint(Buffer.alloc(32, 0), 0xffffffff),
    script: cbScript,
    sequence: 0xffffffff
  });

  const addr = Address.fromString(payoutAddr);
  mtx.addOutput({ address: addr, value: gbt.coinbasevalue });

  // witness reserved value (32 bytes zeros)
  mtx.inputs[0].witness.push(Buffer.alloc(32, 0));

  if (gbt.default_witness_commitment) {
    const commitScript = Script.fromRaw(Buffer.from(gbt.default_witness_commitment, 'hex'));
    mtx.addOutput({ script: commitScript, value: 0 });
  }

  return mtx.toTX() as TXType;
}

function buildFullBlock_bcoin(job: Job, coinbaseTx: TXType, versionBE: number, ntime: number, nonceBE: number): BlockType {
  const block = new Block();
  block.version = versionBE >>> 0;
  block.prevBlock = Buffer.from(job.gbt.previousblockhash, 'hex').reverse();
  block.time = ntime >>> 0;
  block.bits = parseInt(job.nbits, '16') >>> 0;
  block.nonce = nonceBE >>> 0;

  block.txs.push(coinbaseTx);
  for (const tx of job.gbt.transactions) {
    block.txs.push(TX.fromRaw(Buffer.from(tx.data, 'hex')));
  }

  block.refresh(); // compute merkle/witness roots
  return block as BlockType;
}

/* ===== ASICBoost version-rolling ===== */
function validateRolledVersion(baseVersion: number, submittedVersion: number, mask: bigint): boolean {
  const base = BigInt(baseVersion >>> 0);
  const sub = BigInt(submittedVersion >>> 0);
  const keepMask = ~mask & 0xffffffffn;
  return ((base & keepMask) === (sub & keepMask));
}

/* ===== Stratum ===== */
const clients = new Map<net.Socket, ClientState>();

function json(socket: net.Socket, id: any, result: any, error: any = null) {
  socket.write(JSON.stringify({ id, result, error }) + '\n');
}

function sendNotify(socket: net.Socket, job: Job) {
  const params = [
    job.jobId,
    job.prevhashLE,
    job.coinb1,
    job.coinb2,
    job.merkleBranchesLE,
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

/* ===== Submit ===== */
async function submitBlock(hexBlock: string) {
  return rpc('submitblock', [hexBlock], 3);
}

/* ===== ZMQ 新块推送 ===== */
async function subscribeZmqNewBlock() {
  const sock = new zmq.Subscriber();
  sock.connect(ZMQ_BLOCK);
  sock.subscribe('hashblock');
  console.log(`ZMQ: Subscribed to new block notifications at ${ZMQ_BLOCK}`);

  for await (const [topic, message] of sock) {
    if (topic.toString() === 'hashblock') {
      const blockHash = message.toString('hex');
      console.log(`ZMQ: New block detected ${blockHash}, refreshing job...`);
      try {
        const gbt = await getTemplate();
        currentJob = buildJob(gbt);
        for (const [sock] of clients) sendNotify(sock, currentJob);
      } catch (e) {
        console.error('ZMQ: Failed to refresh job after new block:', e);
      }
    }
  }
}

/* ===== Main ===== */
let currentJob: Job;

async function main() {
  try {
    currentJob = buildJob(await getTemplate());
    console.log(`Initial job created for height ${currentJob.gbt.height}`);
  } catch (e) {
    console.error('Failed to create initial job:', e);
    process.exit(1);
  }

  // 定时刷新（兜底）
  setInterval(async () => {
    try {
      const gbt = await getTemplate();
      if (
        gbt.previousblockhash !== currentJob.gbt.previousblockhash ||
        gbt.curtime !== currentJob.gbt.curtime ||
        gbt.transactions.length !== currentJob.gbt.transactions.length
      ) {
        currentJob = buildJob(gbt);
        console.log(`New job created for height ${currentJob.gbt.height}`);
        for (const [sock] of clients) sendNotify(sock, currentJob);
      }
    } catch (e) {
      console.error('GBT refresh failed:', e);
    }
  }, REFRESH_MS);

  // 启动 ZMQ 推送监听
  subscribeZmqNewBlock().catch(e => console.error('ZMQ subscription error:', e));

}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
