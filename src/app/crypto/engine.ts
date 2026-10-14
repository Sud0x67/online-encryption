import { buffer, decode, encode } from './encoding';
import { algorithmById, ALGORITHMS } from './registry';
import { CryptoRequest, CryptoResult } from './types';
const HASHES: Record<string, string> = {
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512',
};
export async function runCrypto({
  algorithm: id,
  params: p,
}: CryptoRequest): Promise<CryptoResult> {
  if (!ALGORITHMS.some((a) => a.id === id)) throw new Error('未知算法。');
  const a = algorithmById(id);
  const cipher = a.category === 'symmetric' || a.category === 'asymmetric';
  if (cipher ? !['encrypt', 'decrypt'].includes(p.operation) : p.operation !== 'compute')
    throw new Error('该算法不支持当前操作。');
  if (a.modes && !a.modes.includes(p.mode)) throw new Error('该算法不支持所选模式。');
  if (!['pkcs7', 'none'].includes(p.padding)) throw new Error('不支持的填充方式。');
  if (
    id === 'rsa' &&
    (!['OAEP', 'PKCS1'].includes(p.rsaScheme) || !['SHA-1', 'SHA-256'].includes(p.hash))
  )
    throw new Error('不支持的 RSA 参数。');
  if (id === 'sm2' && !['C1C3C2', 'C1C2C3'].includes(p.sm2Order))
    throw new Error('不支持的 SM2 密文顺序。');
  const input = decode(p.input, p.inputEncoding);
  let data: Uint8Array;
  let tag: Uint8Array | undefined;
  if (a.category === 'symmetric') {
    const { symmetric } = await import('./symmetric');
    const result = await symmetric(
      id,
      p,
      input,
      decode(p.key, p.keyEncoding),
      p.mode === 'ECB' ? new Uint8Array() : decode(p.iv, p.ivEncoding),
      p.mode === 'GCM' ? decode(p.aad, p.aadEncoding) : new Uint8Array(),
      p.mode === 'GCM' && p.operation === 'decrypt'
        ? decode(p.tag, p.tagEncoding)
        : new Uint8Array(),
    );
    data = result.data;
    tag = result.tag;
  } else if (id === 'rsa') {
    data = await (await import('./rsa')).rsa(p, input);
  } else if (id === 'sm2') {
    data = await (await import('./sm2')).sm2Cipher(p, input);
  } else if (HASHES[id]) {
    data = new Uint8Array(await crypto.subtle.digest(HASHES[id], buffer(input)));
  } else if (id === 'hmac') {
    if (!['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].includes(p.hash))
      throw new Error('不支持的 HMAC 摘要。');
    const bytes = decode(p.key, p.keyEncoding);
    if (!bytes.length) throw new Error('HMAC 密钥不能为空。');
    const key = await crypto.subtle.importKey(
      'raw',
      buffer(bytes),
      { name: 'HMAC', hash: p.hash },
      false,
      ['sign'],
    );
    data = new Uint8Array(await crypto.subtle.sign('HMAC', key, buffer(input)));
  } else if (id === 'md5') {
    const { default: forge } = await import('node-forge');
    const md = forge.md.md5.create();
    md.update(forge.util.hexToBytes(encode(input, 'hex')));
    data = decode(md.digest().toHex(), 'hex');
  } else if (id === 'sm3') {
    data = decode((await import('sm-crypto')).default.sm3(Array.from(input)), 'hex');
  } else {
    data = input;
  }
  return {
    output: encode(data, p.outputEncoding),
    ...(tag ? { tag: encode(tag, p.tagEncoding) } : {}),
    bytes: data.length,
  };
}
