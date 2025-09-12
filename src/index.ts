import net from 'net';
import crypto from 'crypto';
import zmq from 'zeromq';
import {
  addressToScriptPubKey, dsha256, toLE, u64, varint,
  merkleBranchesForCoinbaseAt0, bitsToTargetHex
} from './utils.js';
import { rpc } from './rpc.js';

// @ts-ignore: bcoin 无官方 TS 类型
import bcoin from 'bcoin';
const { Block, TX, MTX, Script, Outpoint, Address } = bcoin;
type TXType = InstanceType<typeof TX>;
type BlockType = InstanceType<typeof Block>;

/* ===== Env ===== */
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
  default_witness_commitment?: string;
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

/* Pack 80-byte header from fields */
function packHeader(versionHex: string, prevhashBE: string, merkleRootLE: Buffer, ntimeHex8: string, nbitsHex: string, nonceHex8: string) {
  // Merkle root in header is big-endian; we keep LE chain then reverse once here.
  return Buffer.concat([
    Buffer.from(versionHex, 'hex').reverse(),
    Buffer.from(prevhashBE, 'hex').reverse(),
    Buffer.from(merkleRootLE).reverse(),
    Buffer.from(ntimeHex8, 'hex').reverse(),
    Buffer.from(nbitsHex, 'hex').reverse(),
    Buffer.from(nonceHex8, 'hex').reverse()
  ]);
}

/* Constant-time-ish 256-bit big-endian compare: a <= b */
function cmp256(aBE: Buffer, bBE: Buffer) {
  for (let i = 0; i < 32; i++) {
    if (aBE[i] < bBE[i]) return true;
    if (aBE[i] > bBE[i]) return false;
  }
  return true;
}

/* ===== Coinbase scriptSig builder (dedup) ===== */
/* Consensus safety: enforce scriptSig length 2 ~ 100 bytes */
function buildCoinbaseScriptSig(height: number, extra: Buffer): Buffer {
  const heightScript = encodeScriptNumber(height);
  const tag = Buffer.from(COINBASE_TAG);
  const scriptSig = Buffer.concat([
    pushData(heightScript),
    pushData(tag),
    pushData(extra)
  ]);
  if (scriptSig.length < 2 || scriptSig.length > 100) {
    throw new Error(`coinbase scriptSig length out of bounds: ${scriptSig.length} (expected 2~100)`);
  }
  return scriptSig;
}

/* ===== RPC wrappers ===== */
async function getTemplate(): Promise<Gbt> {
  return rpc<Gbt>('getblocktemplate', [{ rules: ['segwit'] }], 3);
}
async function submitBlock(hexBlock: string) {
  try {
    const result = await rpc<string | null>('submitblock', [hexBlock], 3);
    if (result === null) {
      console.log(`submitBlock: Block accepted by node`);
      return true;
    }
    console.warn(`submitBlock: Block rejected by node, reason=${result}`);
    return false;
  } catch (err) {
    console.error(`submitBlock: RPC error`, err);
    return false;
  }
}

/* ===== Job builder ===== */
function buildJob(gbt: Gbt, clean: boolean): Job {
  const mark = cryptoRandom(8);
  const cbMarked = buildCoinbaseRaw(mark, gbt.height, gbt.coinbasevalue);
  const idx = cbMarked.indexOf(mark);
  if (idx < 0) throw new Error('Internal error: mark not found in coinbase');
  const coinb1 = cbMarked.slice(0, idx).toString('hex');
  const coinb2 = cbMarked.slice(idx + mark.length).toString('hex');

  const nonCbTxidsBE = gbt.transactions.map(t => t.txid || t.hash).filter((x): x is string => !!x);
  const merkleBranchesLE = merkleBranchesForCoinbaseAt0(nonCbTxidsBE);

  // ntime 提前 2 秒，缓冲网络延迟/丢包/本地 I/O 等
  const adjustedTime = gbt.curtime + 2;

  return {
    jobId: Buffer.from(`${gbt.height}-${Date.now().toString(16)}`).toString('hex'),
    coinb1,
    coinb2,
    merkleBranchesLE,
    versionHex: gbt.version.toString(16).padStart(8, '0'),
    versionBE: gbt.version >>> 0,
    prevhashLE: toLE(gbt.previousblockhash).toString('hex'),
    prevhashBE: gbt.previousblockhash,
    nbits: gbt.bits,
    ntime: adjustedTime.toString(16).padStart(8, '0'),
    clean,
    targetHex: bitsToTargetHex(gbt.bits),
    gbt
  };
}

function buildCoinbaseRaw(extra: Buffer, height: number, value: number) {
  const scriptSig = buildCoinbaseScriptSig(height, extra);
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
  cbScript.fromRaw(buildCoinbaseScriptSig(gbt.height, extraNonce));
  mtx.addInput({
    prevout: new Outpoint(Buffer.alloc(32, 0), 0xffffffff),
    script: cbScript,
    sequence: 0xffffffff
  });
  const addr = Address.fromString(payoutAddr);
  mtx.addOutput({ address: addr, value: gbt.coinbasevalue });
  // Ensure witness commitment output is present when template requests it
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
  block.bits = parseInt(job.nbits, 16) >>> 0;
  block.nonce = nonceBE >>> 0;
  block.txs.push(coinbaseTx);
  for (const tx of job.gbt.transactions) {
    block.txs.push(TX.fromRaw(Buffer.from(tx.data, 'hex')));
  }
  block.refresh();
  return block as BlockType;
}

/* ===== ASICBoost version-rolling ===== */
function validateRolledVersion(baseVersion: number, submittedVersion: number, mask: bigint): boolean {
  const base = BigInt(baseVersion >>> 0);
  const sub = BigInt(submittedVersion >>> 0);
  const keepMask = ~mask & 0xffffffffn;
  // Keep bits must match; rolled bits must be within mask
  return ((base & keepMask) === (sub & keepMask)) && ((sub ^ base) === ((sub ^ base) & mask));
}

/* ===== Stratum ===== */
const clients = new Map<net.Socket, ClientState>();

function json(socket: net.Socket, id: any, result: any, error: any = null) {
  socket.write(JSON.stringify({ id, result, error }) + '\n');
}

function sendNotifyTo(socket: net.Socket, job: Job) {
  // Sync job into client state to prevent jobId mismatch
  const st = clients.get(socket);
  if (st) st.jobs.set(job.jobId, job);

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
  // 兜底：再次下发难度，确保矿机同步
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

/* ===== ZMQ 新块推送（带自动重连） ===== */
async function subscribeZmqNewBlock() {
  let sock: zmq.Subscriber | undefined;
  try {
    sock = new zmq.Subscriber();
    sock.connect(ZMQ_BLOCK);
    sock.subscribe('hashblock');
    console.log(`ZMQ: Subscribed to new block notifications at ${ZMQ_BLOCK}`);

    for await (const [topic, message] of sock) {
      if (topic.toString() === 'hashblock') {
        console.log(`ZMQ: New block ${message.toString('hex')}, refreshing job...`);
        try {
          const gbt = await getTemplate();
          currentJob = buildJob(gbt, true); // 新区块 clean_jobs = true
          for (const [clientSock] of clients) sendNotifyTo(clientSock, currentJob);
        } catch (e) {
          console.error('ZMQ refresh error:', e);
        }
      }
    }
  } catch (err) {
    console.error('ZMQ subscription error:', err);
  } finally {
    if (sock) {
      try { sock.close(); } catch {}
    }
    console.log('Reconnecting to ZMQ in 5s...');
    setTimeout(() => { subscribeZmqNewBlock().catch(console.error); }, 5000);
  }
}

/* ===== Main ===== */
let currentJob: Job;

async function main() {
  currentJob = buildJob(await getTemplate(), true);
  console.log(`Initial job created for height ${currentJob.gbt.height}`);

  // 定时刷新兜底（非新区块 clean_jobs = false）
  setInterval(async () => {
    try {
      const gbt = await getTemplate();
      if (
        gbt.previousblockhash !== currentJob.gbt.previousblockhash ||
        gbt.curtime !== currentJob.gbt.curtime ||
        gbt.transactions.length !== currentJob.gbt.transactions.length
      ) {
        const isNewBlock = gbt.previousblockhash !== currentJob.gbt.previousblockhash;
        currentJob = buildJob(gbt, isNewBlock);
        console.log(`New job created for height ${currentJob.gbt.height} | clean_jobs=${isNewBlock}`);
        for (const [sock] of clients) sendNotifyTo(sock, currentJob);
      }
    } catch (e) {
      console.error('GBT refresh failed:', e);
    }
  }, REFRESH_MS);

  subscribeZmqNewBlock().catch(e => console.error('ZMQ subscription error:', e));

  const server = net.createServer(socket => {
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    const state: ClientState = {
      id: Math.floor(Math.random() * 1e9),
      extranonce1: cryptoRandom(4),
      authorized: false,
      extranonceSubscribed: false,
      negotiatedVersionRolling: false,
      versionMaskHex: VERSION_MASK_HEX.startsWith('0x') ? VERSION_MASK_HEX.slice(2) : VERSION_MASK_HEX,
      jobs: new Map([[currentJob.jobId, currentJob]])
    };
    clients.set(socket, state);

    socket.on('data', async buf => {
      const lines = buf.toString().split('\n').map(s => s.trim()).filter(Boolean);
      for (const line of lines) {
        let msg: any;
        try { msg = JSON.parse(line); } catch { continue; }
        const { id, method, params } = msg;

        if (method === 'mining.configure') {
          state.negotiatedVersionRolling = true;
          json(socket, id, { 'version-rolling': true, 'version-rolling.mask': state.versionMaskHex });
          sendVersionMask(socket, state.versionMaskHex);
          continue;
        }
        if (method === 'mining.extranonce.subscribe') {
          state.extranonceSubscribed = true;
          json(socket, id, true);
          sendSetExtranonce(socket, state);
          continue;
        }
        if (method === 'mining.subscribe') {
          json(socket, id, [[['mining.set_difficulty', state.id], ['mining.notify', state.id]], state.extranonce1.toString('hex'), EXTRANONCE2_SIZE]);

          // 首次连接：先下发难度，再下发任务，避免矿机用默认难度挖第一批 share
          socket.write(JSON.stringify({
            id: null,
            method: 'mining.set_difficulty',
            params: [SHARE_DIFFICULTY]
          }) + '\n');

          sendNotifyTo(socket, currentJob);

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
          if (!state.authorized) { json(socket, id, false, { code: 24, message: 'Unauthorized' }); continue; }
          const [worker, jobId, en2, ntimeHex, nonceHex, subVerHex] = params;
          const job = state.jobs.get(jobId) || currentJob;

          // Extranonce2 size guard
          if (typeof en2 !== 'string' || en2.length !== EXTRANONCE2_SIZE * 2) {
            json(socket, id, false, { code: 20, message: 'Invalid extranonce2 size' });
            continue;
          }

          // Build coinbase hex (coinb1 + en1 + en2 + coinb2)
          const coinbaseHex = job.coinb1 + state.extranonce1.toString('hex') + en2 + job.coinb2;

          // Merkle root calculation: keep LE throughout the chain
          let rootLE = dsha256(Buffer.from(coinbaseHex, 'hex')); // coinbase txid as LE bytes
          for (const branchHexLE of job.merkleBranchesLE) {
            const branchLE = Buffer.from(branchHexLE, 'hex');
            rootLE = dsha256(Buffer.concat([rootLE, branchLE]));
          }

          // Version rolling
          let versionHex = job.versionHex;
          let versionBE = job.versionBE;
          if (subVerHex && state.negotiatedVersionRolling) {
            const subV = parseInt(subVerHex, 16) >>> 0;
            if (!validateRolledVersion(job.versionBE, subV, VERSION_MASK)) {
              json(socket, id, false, { code: 22, message: 'Invalid version rolling beyond mask' });
              continue;
            }
            versionHex = subV.toString(16).padStart(8, '0');
            versionBE = subV >>> 0;
          }

          // Check target: hash header, reverse to BE, compare with BE target
          const header = packHeader(versionHex, job.prevhashBE, rootLE, ntimeHex, job.nbits, nonceHex);
          const headerHashBE = Buffer.from(dsha256(header)).reverse();
          const targetBE = Buffer.from(job.targetHex, 'hex');
          const meets = cmp256(headerHashBE, targetBE);

          if (meets) {
            console.log(`Potential block found by ${worker} | height=${job.gbt.height}`);
            try {
              const extraNonce = Buffer.from(state.extranonce1.toString('hex') + en2, 'hex');
              const coinbaseTX = buildCoinbaseTX_bcoin(job.gbt, extraNonce, PAYOUT_ADDRESS);
              const ntimeBE = parseInt(ntimeHex, 16) >>> 0;
              const nonceBE = parseInt(nonceHex, 16) >>> 0;
              const block = buildFullBlock_bcoin(job, coinbaseTX, versionBE, ntimeBE, nonceBE);
              const raw = block.toRaw();
              const ok = await submitBlock(raw.toString('hex'));
              if (ok) {
                console.log(`BLOCK ACCEPTED by ${worker} | height=${job.gbt.height} | version=${versionHex}`);
              } else {
                console.warn(`BLOCK REJECTED by node | height=${job.gbt.height} | version=${versionHex}`);
              }
            } catch (e) {
              console.error('Block construction/submission error:', e);
            }
          } else {
            console.log(`Share accepted from ${worker} | height=${job.gbt.height}`);
          }

          json(socket, id, true);
          continue;
        }

        // 未知方法
        json(socket, id, null, { code: -3, message: 'Unknown method' });
      }
    });

    socket.on('close', () => {
      console.log(`Client ${remote} disconnected`);
      clients.delete(socket);
    });

    socket.on('error', (err) => {
      console.error(`Socket error for ${remote}:`, err);
      clients.delete(socket);
    });
  });

  server.listen(parseInt(PORT, 10), HOST, () => {
    console.log(`Stratum solo server listening on ${HOST}:${PORT}`);
    console.log(`Payout address: ${PAYOUT_ADDRESS}`);
    console.log(`ASICBoost mask: ${VERSION_MASK_HEX}`);
    console.log(`Share difficulty: ${SHARE_DIFFICULTY}`);
  });

  server.on('error', (err) => {
    console.error('Server error:', err);
    process.exit(1);
  });
}

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection at:', promise, 'reason:', reason);
});

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
