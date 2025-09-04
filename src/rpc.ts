import http from 'http';
import https from 'https';

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8332';
const RPC_USER = process.env.RPC_USER || 'user';
const RPC_PASS = process.env.RPC_PASS || 'pass';

export async function rpc<T = any>(method: string, params: any[] = [], retries = 3): Promise<T> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await new Promise<T>((resolve, reject) => {
        const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
        const url = new URL(RPC_URL);
        const client = url.protocol === 'https:' ? https : http;
        const req = client.request({
          hostname: url.hostname,
          port: url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80),
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
    } catch (err) {
      if (attempt === retries) throw err;
      console.warn(`RPC ${method} failed (attempt ${attempt}), retrying...`);
      await new Promise(r => setTimeout(r, 1000 * attempt));
    }
  }
  throw new Error(`RPC ${method} failed after ${retries} attempts`);
}
