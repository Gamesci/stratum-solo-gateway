import net from 'net';
import http from 'http';
import crypto from 'crypto';
import {
  addressToScriptPubKey, dsha256, fromLE, toLE, u64, varint
} from './utils.js';

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

type GbtTx = { data: string; txid: string };
type Gbt = {
  version: number;
  previousblockhash: string;
  transactions: GbtTx[];
  coinbasevalue: number;
  bits: string;
  curtime: number;
  height: number;
};

const scriptPubKey = addressToScriptPubKey(PAYOUT_ADDRESS);

function buildCoinbase(extra: Buffer, height: number, value: number) {
  const heightScript = Buffer.concat([Buffer.from([height])]);
  const tag = Buffer.from(COINBASE_TAG);
  const scriptSig = Buffer.concat([
    Buffer.from([heightScript.length]), heightScript,
    Buffer.from([tag.length]), tag,
    Buffer.from([extra.length]), extra
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

async function getTemplate(): Promise<Gbt> {
  return rpc<Gbt>('getblocktemplate', [{ rules: ['segwit'] }]);
}

function buildJob(gbt: Gbt) {
  const mark = crypto.randomBytes(8);
  const cbMarked = buildCoinbase(mark, gbt.height, gbt.coinbasevalue);
  const idx = cbMarked.indexOf(mark);
  const coinb1 = cbMarked.slice(0, idx).toString('hex');
  const coinb2 = cbMarked.slice(idx + mark.length).toString('hex');
  const branches = gbt.transactions.map(t => fromLE(toLE(t.txid)));
  return {
    jobId: `${gbt.height}-${Date.now()}`,
    coinb1, coinb2,
    merkleBranches: branches,
    version: gbt.version.toString(16).padStart(8, '0'),
    prevhash: toLE(gbt.previousblockhash).toString('hex'),
    nbits: gbt.bits,
    ntime: gbt.curtime.toString(16),
    clean: true,
    targetHex: bitsToTargetHex(gbt.bits),
    gbt
  };
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

function packHeader(job: any, merkleRoot: Buffer, ntimeHex: string, nonceHex: string) {
  const verLE = Buffer.from(job.version, 'hex').reverse();
  const prevLE = Buffer.from(job.prevhash, 'hex').reverse();
  const rootLE = Buffer.from(merkleRoot).reverse();
  const ntimeLE = Buffer.from(ntimeHex, 'hex').reverse();
  const nbitsLE = Buffer.from(job.nbits, 'hex').reverse();
  const nonceLE = Buffer.from(nonceHex, 'hex').reverse();
  return Buffer.concat([verLE, prevLE, rootLE, ntimeLE, nbitsLE, nonceLE]);
}

function cmp256(a: Buffer, b: Buffer) {
  for (let i = 0; i < 32; i++) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return true;
}

async function submitBlock(hexBlock: string) {
  return rpc('submitblock', [hexBlock]);
}

function buildBlockHex(job: any, coinbaseFull: Buffer, merkleRootBuf: Buffer, ntimeHex: string, nonceHex: string) {
  const header = packHeader(job, merkleRootBuf, ntimeHex, nonceHex);
  const txs = [coinbaseFull, ...job.gbt.transactions.map((t: any) => Buffer.from(t.data, 'hex'))];
  return Buffer.concat([
    header,
    varint(txs.length),
    ...txs
  ]).toString('hex');
}

function json(socket: net.Socket, id: any, result: any, error: any = null) {
  socket.write(JSON.stringify({ id, result, error }) + '\n');
}

function notify(socket: net.Socket, job: any) {
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
  socket.write(JSON.stringify({ id: null, method: 'mining.notify', params }) + '\n');
  socket.write(JSON.stringify({ id: null, method: 'mining.set_difficulty', params: [16384] }) + '\n');
}

async function main() {
  let currentJob = buildJob(await getTemplate());

  setInterval(async () => {
    try {
      const gbt = await getTemplate();
      if (gbt.previousblockhash !== currentJob.gbt.previousblockhash || gbt.curtime !== currentJob.gbt.curtime) {
        currentJob = buildJob(gbt);
        for (const [sock] of clients) {
          notify(sock, currentJob);
        }
      }
    } catch (e) {
      console.error('GBT refresh failed:', e);
    }
  }, REFRESH_MS);

  const server = net.createServer(socket => {
    clients.set(socket, true);

    socket.on('data', async data => {
      for (const line of data.toString().trim().split('\n')) {
        if (!line.trim()) continue;
        let msg: any;
        try { msg = JSON.parse(line); } catch { continue; }
        const { id, method, params } = msg;

        if (method === 'mining.subscribe') {
          json(socket, id, [[['mining.set_difficulty', 1], ['mining.notify', 1]], '00000001', EXTRANONCE2_SIZE]);
          notify(socket, currentJob);
        } else if (method === 'mining.authorize') {
          json(socket, id, true);
        } else if (method === 'mining.submit') {
          const [_worker, jobId, en2, ntimeHex, nonceHex] = params;
          const coinbaseHex = currentJob.coinb1 + '00000001' + en2 + currentJob.coinb2;
          const coinbaseBuf = Buffer.from(coinbaseHex, 'hex');
          let root = dsha256(coinbaseBuf);
          for (const branchHex of currentJob.merkleBranches) {
            const branch = Buffer.from(branchHex, 'hex');
            root = dsha256(Buffer.concat([root, branch]));
          }
          const header = packHeader(currentJob, root, ntimeHex, nonceHex);
          const headerHash = dsha256(header);
          const target = Buffer.from(currentJob.targetHex, 'hex');

          if (cmp256(headerHash.reverse(), target)) {
            const blockHex = buildBlockHex(currentJob, coinbaseBuf, root, ntimeHex, nonceHex);
            try {
              await submitBlock(blockHex);
              console.log('BLOCK FOUND and submitted:', currentJob.jobId);
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

const clients = new Map<net.Socket, boolean>();
main().catch(e => { console.error(e); process.exit(1); });
