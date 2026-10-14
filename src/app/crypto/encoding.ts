import { Encoding } from './types';
export function decode(value: string, encoding: Encoding): Uint8Array {
  if (encoding === 'utf8') return new TextEncoder().encode(value);
  const text = value.replace(/\s/g, '');
  if (encoding === 'hex') {
    if (text.length % 2 || !/^[0-9a-f]*$/i.test(text))
      throw new Error('Hex 必须为偶数位十六进制字符。');
    return Uint8Array.from(text.match(/../g) ?? [], (byte) => parseInt(byte, 16));
  }
  if (encoding !== 'base64') throw new Error('不支持的编码。');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))
    throw new Error('Base64 格式无效，请保留标准填充符 =。');
  const bytes = Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
  if (encode(bytes, 'base64') !== text) throw new Error('Base64 包含非规范的尾部位。');
  return bytes;
}
export function encode(bytes: Uint8Array, encoding: Encoding): string {
  if (encoding === 'hex')
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  if (encoding === 'base64') {
    let text = '';
    for (let i = 0; i < bytes.length; i += 8192)
      text += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(text);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('结果不是有效 UTF-8，请切换为 Hex 或 Base64 输出后重试。');
  }
}
export function buffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}
export function pkcs7Pad(bytes: Uint8Array, size: number): Uint8Array {
  const count = size - (bytes.length % size);
  const out = new Uint8Array(bytes.length + count);
  out.set(bytes);
  out.fill(count, bytes.length);
  return out;
}
export function pkcs7Unpad(bytes: Uint8Array, size: number): Uint8Array {
  const count = bytes[bytes.length - 1];
  if (
    !bytes.length ||
    bytes.length % size ||
    !count ||
    count > size ||
    !bytes.subarray(bytes.length - count).every((b) => b === count)
  )
    throw new Error('PKCS#7 填充无效，请检查密钥、IV 或密文。');
  return bytes.slice(0, -count);
}
