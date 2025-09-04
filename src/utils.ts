import { bech32 } from 'bech32';
import crypto from 'crypto';

export function sha256(buf: Buffer) {
  return crypto.createHash('sha256').update(buf).digest();
}
export function dsha256(buf: Buffer) {
  return sha256(sha256(buf));
}
export function toLE(hex: string) {
  return Buffer.from(hex, 'hex').reverse();
}
export function fromLE(buf: Buffer) {
  return Buffer.from(buf).reverse().toString('hex');
}

export function varint(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) return Buffer.concat([Buffer.from([0xfd]), u16(n)]);
  if (n <= 0xffffffff) return Buffer.concat([Buffer.from([0xfe]), u32(n)]);
  return Buffer.concat([Buffer.from([0xff]), u64(BigInt(n))]);
}
export function u16(n: number) {
  const b = Buffer.allocUnsafe(2); b.writeUInt16LE(n, 0); return b;
}
export function u32(n: number) {
  const b = Buffer.allocUnsafe(4); b.writeUInt32LE(n, 0); return b;
}
export function u64(n: bigint) {
  const b = Buffer.allocUnsafe(8);
  b.writeUInt32LE(Number(n & 0xffffffffn), 0);
  b.writeUInt32LE(Number((n >> 32n) & 0xffffffffn), 4);
  return b;
}

export function merkleRoot(txidsLE: Buffer[]) {
  if (txidsLE.length === 0) return Buffer.alloc(32, 0);
  let layer = txidsLE.slice();
  while (layer.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const a = layer[i];
      const b = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(dsha256(Buffer.concat([a, b])));
    }
    layer = next;
  }
  return layer[0];
}

export type ScriptPubKey = Buffer;

export function addressToScriptPubKey(addr: string): ScriptPubKey {
  if (addr.startsWith('bc1') || addr.startsWith('tb1') || addr.startsWith('bcrt1')) {
    const dec = bech32.decode(addr);
    const data = bech32.fromWords(dec.words.slice(1));
    if (data.length === 20) {
      return Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.from(data)]);
    } else if (data.length === 32) {
      return Buffer.concat([Buffer.from([0x00, 0x20]), Buffer.from(data)]);
    }
    throw new Error('Unsupported Bech32 program length');
  }
  const payload = base58checkDecode(addr);
  const ver = payload[0];
  const h = payload.slice(1);
  if (ver === 0x00) {
    return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h, Buffer.from([0x88, 0xac])]);
  } else if (ver === 0x05) {
    return Buffer.concat([Buffer.from([0xa9, 0x14]), h, Buffer.from([0x87])]);
  }
  throw new Error('Unsupported base58 address');
}

function base58checkDecode(addr: string): Buffer {
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let x = 0n;
  for (const c of addr) {
    const i = ALPH.indexOf(c);
    if (i === -1) throw new Error('Bad base58');
    x = x * 58n + BigInt(i);
  }
  let bytes: number[] = [];
  while (x > 0) {
    bytes.push(Number(x & 0xffn));
    x >>= 8n;
  }
  bytes = bytes.reverse();
  for (const c of addr) {
    if (c === '1') bytes.unshift(0);
    else break;
  }
  const buf = Buffer.from(bytes);
  const body = buf.slice(0, -4);
  const cksum = buf.slice(-4);
  const hash = sha256(sha256(body));
  if (!hash.slice(0, 4).equals(cksum)) throw new Error('Bad checksum');
  return body;
}
