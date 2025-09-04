import net from 'net';
import http from 'http';
import { addressToScriptPubKey, dsha256, fromLE, merkleRoot, toLE, u32, varint } from './utils.js';

type RpcReq = { method: string; params?: any[]; id?: number };
type RpcRes<T=any> = { result: T; error: any; id: number };

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8332';
const RPC_USER = process.env.RPC_USER || 'user';
const RPC_PASS = process.env.RPC_PASS || 'pass';
const [HOST, PORT] = (process.env.LISTEN || '0.0.0.0:3333').split(':');
const PAYOUT_ADDRESS = process.env.PAYOUT_ADDRESS!;
const COINBASE_TAG = (process.env.COINBASE_TAG || '/SoloGateway/').trim();
const EXTRANONCE2_SIZE = parseInt(process.env.EXTRANONCE2_SIZE || '4', 10);
const REFRESH_MS = parseInt(process.env.REFRESH_MS || '10000', 10);

if (!PAYOUT_ADDRESS) throw new Error('PAYOUT_ADDRESS required');

function rpc<T=any>(method: string, params: any[] = []): Promise<T> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const url = new URL(RPC_URL);
    const req = http.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      auth: `${RPC_USER}:${RPC_PASS}`,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data) as RpcRes<T>;
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

type GbtTx = {
  data: string;
  txid: string;
  hash?: string;
  depends: number[];
  fee: number;
  weight: number;
};
type Gbt = {
  version: number;
  previousblockhash: string;
  transactions: GbtTx[];
  coinbaseaux: { flags?: string };
  coinbasevalue: number;
  longpollid?: string;
  target: string;
  bits: string;
  curtime: number;
  height: number;
  rules: string[];
  default_witness_commitment?: string;
};

type Job = {
  jobId: string;
  coinb1: string;
  coinb2: string;
  merkleBranches: string[];
  version: string;
  prevhash: string;
  nbits: string;
  ntime: string;
  clean: boolean;
  targetHex: string; // full 256-bit target
  gbt: Gbt;
};

const clients = new Map<net.Socket, {
  id: number;
  extranonce1: Buffer;
  difficulty: number;
  authorized: boolean;
  jobs: Map<string, Job>;
}>();

const scriptPubKey = addressToScriptPubKey(PAYOUT_ADDRESS);

function buildCoinbase(txExtra: Buffer, height: number, coinbaseValue: number) {
  // coinbase input: height (BIP34) + tag + extra (extranonce1+2)
  const heightScript = Buffer.concat([encodeScriptNumber(height)]);
  const tag = Buffer.from(COINBASE_TAG);
  // scriptSig
  const scriptSig = Buffer.concat([
    pushData(heightScript),
    pushData(tag),
    pushData(txExtra)
  ]);
  const coinbaseIn = Buffer.concat([
    Buffer.alloc(32, 0), // prevout hash
    Buffer.alloc(4, 0xff), // prevout index 0xffffffff
    varint(scriptSig.length),
    scriptSig,
    Buffer.from('ffffffff', 'hex') // sequence
  ]);
  // coinbase output: to PAYOUT scriptPubKey
  const outputValue = u64(BigInt(coinbaseValue)); // satoshis
  const out = Buffer.concat([
    outputValue,
    varint(scriptPubKey.length),
    scriptPubKey
  ]);

  // witness commitment (if required) will be placed as OP_RETURN output by template default_witness_commitment; we honor GBT transactions list instead of inventing it.
  const tx = Buffer.concat([
    Buffer.from('01000000', 'hex'), // version
    varint(1), coinbaseIn,
    varint(1), out,
    Buffer.from('00000000', 'hex') // locktime
  ]);
  return tx;
}

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
  // Minimal encoding for positive numbers (height)
  const out: number[] = [];
  let x = n >>> 0;
  while (x > 0) {
    out.push(x & 0xff);
    x >>= 8;
  }
  if (out.length === 0) out.push(0);
  // make it a single push
  return Buffer.from(out);
}

function getTargetFromBits(bitsHex: string): Buffer {
  const bits = Buffer.from(bitsHex, 'hex').reverse();
  const exp = bits[3];
  const mant = bits.readUInt32LE(0) & 0x00ffffff;
  let target = Buffer.alloc(32, 0);
  const mantBuf = Buffer.alloc(4); mantBuf.writeUInt32BE(mant, 0);
  const shift = exp - 3;
  const start = 32 - shift - 3;
  target.set(mantBuf.slice(1), start);
  return target;
}

function targetToHex(target: Buffer) {
  return target.toString('hex');
}

async function getTemplate(): Promise<Gbt> {
  const gbt = await rpc<Gbt>('getblocktemplate', [{
    rules: ['segwit']
  }]);
  return gbt;
}

function buildJob(gbt: Gbt): Job {
  const jobId = `${gbt.height}-${gbt.curtime}-${Math.random().toString(16).slice(2, 10)}`;

  // coinbase split: coinb1 + coinb2; miners will insert extranonce1 + extranonce2 in the middle
  const coinbasePrefixExtraPlaceholder = Buffer.alloc(0); // will be extranonce data later
  const coinbase = buildCoinbase(coinbasePrefixExtraPlaceholder, gbt.height, gbt.coinbasevalue);
  // Find where to splice extranonce: our coinbase builder places txExtra as pushData in scriptsig third push.
  // We rebuild coinbase with empty txExtra, then split around that last push's data position:
  // Simple approach: regenerate coinbase with marker 8 bytes, split on marker.
  const MARK = cryptoRandom(8);
  const coinbaseWithMark = buildCoinbase(MARK, gbt.height, gbt.coinbasevalue);
  const idx = coinbaseWithMark.indexOf(MARK);
  if (idx < 0) throw new Error('Failed to locate extranonce splice point');
  const coinb1 = coinbaseWithMark.slice(0, idx).toString('hex');
  const coinb2 = coinbaseWithMark.slice(idx + MARK.length).toString('hex');

  // Merkle branches from non-coinbase txids
  const txidsLE = gbt.transactions.map(t => toLE(t.txid));
  const branches: string[] = [];
  // Per Stratum, miners compute: H = dsha256(coinbase) then apply branches sequentially
  // We provide all branches so miner can compute final merkle root
  let layer = txidsLE.slice();
  // If there are N txs, branches for coinbase is the sibling path to root.
  // Build a full tree and extract path for position 0 (coinbase).
  function buildTree(nodes: Buffer[]): Buffer[][] {
    const levels: Buffer[][] = [nodes];
    while (nodes.length > 1) {
      const next: Buffer[] = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const a = nodes[i];
        const b = i + 1 < nodes.length ? nodes[i + 1] : nodes[i];
        next.push(dsha256(Buffer.concat([a, b])));
      }
      nodes = next;
      levels.push(nodes);
    }
    return levels;
  }
  const base = [dsha256(Buffer.alloc(0))]; // placeholder; we don't need actual coinbase hash here to compute siblings
  const firstLevel = [Buffer.alloc(32, 0), ...txidsLE]; // coinbase position 0, siblings start at txids[0]
  const levels = buildTree(firstLevel);
  // Extract siblings at each level for index 0
  for (let i = 0; i < levels.length - 1; i++) {
    const L = levels[i];
    if (L.length <= 1) break;
    const sibling = L[1] || L[0]; // for index 0, sibling is 1
    branches.push(fromLE(sibling));
  }

  const prevhash = toLE(gbt.previousblockhash).toString('hex');
  const nbits = gbt.bits;
  const ntime = gbt.curtime.toString(16);

  const target = getTargetFromBits(nbits);
  return {
    jobId,
    coinb1,
    coinb2,
    merkleBranches: branches,
    version: gbt.version.toString(16).padStart(8, '0'),
    prevhash,
    nbits,
    ntime,
    clean: true,
    targetHex: targetToHex(target),
    gbt
  };
}

function cryptoRandom(n: number) {
  return Buffer.from(Array.from({ length: n }, () => Math.floor(Math.random() * 256)));
}

function hex(buf: Buffer) { return buf.toString('hex'); }

function packHeader(job: Job, merkleRoot32: Buffer, ntimeHex: string, nonceHex: string) {
  const verLE = Buffer.from(job.version, 'hex').reverse();
  const prevLE = Buffer.from(job.prevhash, 'hex').reverse();
  const rootLE = Buffer.from(merkleRoot32).reverse();
  const ntimeLE = Buffer.from(ntimeHex, 'hex').reverse();
  const nbitsLE = Buffer.from(job.nbits, 'hex').reverse();
  const nonceLE = Buffer.from(nonceHex, 'hex').reverse();
  return Buffer.concat([verLE, prevLE, rootLE, ntimeLE, nbitsLE, nonceLE]);
}

function cmp256(a: Buffer, b: Buffer) { // return a <= b
  for (let i = 0; i < 32; i++) {
    const x = a[i], y = b[i];
    if (x < y) return true;
    if (x > y) return false;
  }
  return true;
}

async function submitBlock(hexBlock: string) {
  return rpc('submitblock', [hexBlock]);
}

// Build full block when solution meets network target
function buildBlockHex(job: Job, coinbaseFull: Buffer, merkleRootBuf: Buffer, ntimeHex: string, nonceHex: string) {
  const header = packHeader(job, merkleRootBuf, ntimeHex, nonceHex);
  const txs = [coinbaseFull, ...job.gbt.transactions.map(t => Buffer.from(t.data, 'hex'))];
  const raw = Buffer.concat([
    Buffer.from('00000020', 'hex'), // witness flag marker+flag? For segwit, use proper serialization via bcoin ideally.
    header, // 80 bytes
    varint(txs.length),
    ...txs,
  ]);
  // For correctness, better to use bcoin to re-serialize witness transactions; this minimal example assumes GBT supplies raw non-witness data OK for block submission on modern nodes. In production, build via bcoin's Block class.
  return raw.toString('hex');
}

function json(socket: net.Socket, id: any, result: any, error: any = null) {
  const msg = JSON.stringify({ id, result, error });
  socket.write(msg + '\n');
}

function notify(socket: net.Socket, job: Job, extranonce1Hex: string) {
  // Stratum mining.notify
  // params: [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
  const params = [
    job.jobId,
    job.prevhash,
    job.coinb1,
    job.coinb2,
    job.merkleBranches,
    job.version,
    job.nbits,
    job.ntime,
    job.clean
  ];
  const msg = JSON.stringify({ id: null, method: 'mining.notify', params });
  socket.write(msg + '\n');
  // set_difficulty (solo 模式可较高，减少 share)
  const diff = 16384; // example
  const setDiff = JSON.stringify({ id: null, method: 'mining.set_difficulty', params: [diff] });
  socket.write(setDiff + '\n');
}

async function main() {
  let currentJob = await buildJob(await getTemplate());
  setInterval(async () => {
    try {
      const gbt = await getTemplate();
      // 仅在 prevhash 或 time 变化时更新
      if (gbt.previousblockhash !== currentJob.gbt.previousblockhash || gbt.curtime !== currentJob.gbt.curtime) {
        currentJob = await buildJob(gbt);
        for (const [sock, state] of clients) {
          state.jobs.set(currentJob.jobId, currentJob);
          notify(sock, currentJob, state.extranonce1.toString('hex'));
        }
      }
    } catch (e) {
      // swallow; log minimal
      console.error('GBT refresh failed:', e?.toString?.() || e);
    }
  }, REFRESH_MS);

  const server = net.createServer(socket => {
    const state = {
      id: Math.floor(Math.random() * 1e9),
      extranonce1: cryptoRandom(4),
      difficulty: 1,
      authorized: false,
      jobs: new Map<string, Job>([[currentJob.jobId, currentJob]])
    };
    clients.set(socket, state);

    socket.on('data', async (data: Buffer) => {
      for (const line of data.toString().trim().split('\n')) {
        if (!line.trim()) continue;
        let msg: any;
        try { msg = JSON.parse(line); } catch { continue; }
        const { id, method, params } = msg;
        if (method === 'mining.subscribe') {
          const extranonce1 = state.extranonce1.toString('hex');
          const extranonce2_size = EXTRANONCE2_SIZE;
          json(socket, id, [[['mining.set_difficulty', state.id], ['mining.notify', state.id]], extranonce1, extranonce2_size]);
          // immediately notify
          notify(socket, currentJob, extranonce1);
        } else if (method === 'mining.authorize') {
          state.authorized = true;
          json(socket, id, true);
        } else if (method === 'mining.submit') {
          // params: [worker, job_id, extranonce2, ntime, nonce]
          const [_worker, jobId, en2, ntimeHex, nonceHex] = params;
          const job = state.jobs.get(jobId) || currentJob;
          // Rebuild coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
          const coinbaseHex = job.coinb1 + state.extranonce1.toString('hex') + en2 + job.coinb2;
          const coinbaseBuf = Buffer.from(coinbaseHex, 'hex');
          const coinbaseHash = dsha256(coinbaseBuf);
          // Compute merkle root
          let root = coinbaseHash;
          for (const branchHex of job.merkleBranches) {
            const branch = Buffer.from(branchHex, 'hex');
            root = dsha256(Buffer.concat([root, branch]));
          }
          // Build header and hash
          const header = packHeader(job, root, ntimeHex, nonceHex);
          const headerHash = dsha256(header);
          const target = Buffer.from(job.targetHex, 'hex');

          const meets = cmp256(headerHash.reverse(), target);
          if (meets) {
            // Build full block and submit
            const blockHex = buildBlockHex(job, coinbaseBuf, root, ntimeHex, nonceHex);
            try {
              await submitBlock(blockHex);
              console.log('BLOCK FOUND and submitted:', job.jobId);
            } catch (e) {
              console.error('submitblock error:', e);
            }
          }
          json(socket, id, true);
        } else {
          json(socket, id, null, { code: -3, message: 'Unknown method' });
        }
      }
    });

    socket.on('close', () => clients.delete(socket));
    socket.on('error', () => clients.delete(socket));
  });

  server.listen(parseInt(PORT, 10), HOST, () => {
    console.log(`Stratum solo listening on ${HOST}:${PORT}`);
  });
}

main().catch(e => { console.error(e); process.exit(1); });
