import { decode, encode } from './encoding';
import { KeyPair, Parameters } from './types';
const ORDER = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');
export async function generateSm2(): Promise<KeyPair> {
  const { sm2 } = (await import('sm-crypto')).default;
  return sm2.generateKeyPairHex();
}
export async function sm2Cipher(p: Parameters, input: Uint8Array): Promise<Uint8Array> {
  const { sm2 } = (await import('sm-crypto')).default;
  const mode = p.sm2Order === 'C1C3C2' ? 1 : 0;
  if (p.operation === 'encrypt') {
    const pub = p.publicKey.replace(/\s/g, '');
    if (!/^(04[0-9a-f]{128}|0[23][0-9a-f]{64})$/i.test(pub) || !sm2.verifyPublicKey(pub))
      throw new Error('SM2 公钥必须为有效的 04 前缀未压缩点或 02/03 前缀压缩点（Hex）。');
    const cipher = sm2.doEncrypt(Array.from(input), pub, mode);
    return decode((p.c1Prefix ? '04' : '') + cipher, 'hex');
  }
  const priv = p.privateKey.replace(/\s/g, '');
  if (!/^[0-9a-f]{64}$/i.test(priv) || BigInt('0x' + priv) <= 0n || BigInt('0x' + priv) >= ORDER)
    throw new Error('SM2 私钥必须为有效的 32 字节 Hex 标量。');
  let hex = encode(input, 'hex');
  if (p.c1Prefix) {
    if (!hex.startsWith('04')) throw new Error('当前格式要求 SM2 密文带 04 前缀。');
    hex = hex.slice(2);
  }
  if (hex.length < 192 || !sm2.verifyPublicKey('04' + hex.slice(0, 128)))
    throw new Error('SM2 密文长度或 C1 点无效，请检查 04 前缀选项。');
  const plain = sm2.doDecrypt(hex, priv, mode, { output: 'array' });
  if (plain.length !== (hex.length - 192) / 2)
    throw new Error('SM2 完整性验证失败，请检查私钥、密文顺序和密文。');
  // sm-crypto returns [] for both a valid empty message and failed authentication.
  // Verify C3 explicitly for this case using the pinned library's EC arithmetic.
  if (hex.length === 192) {
    const { getGlobalCurve } = (await import('sm-crypto/src/sm2/utils.js')).default;
    const { BigInteger } = (await import('jsbn')).default;
    const shared = getGlobalCurve()
      .decodePointHex('04' + hex.slice(0, 128))
      .multiply(new BigInteger(priv, 16));
    const x = shared.getX().toBigInteger().toString(16).padStart(64, '0');
    const y = shared.getY().toBigInteger().toString(16).padStart(64, '0');
    const expected = (await import('sm-crypto')).default.sm3(Array.from(decode(x + y, 'hex')));
    if (expected !== hex.slice(128))
      throw new Error('SM2 完整性验证失败，请检查私钥、密文顺序和密文。');
  }
  return Uint8Array.from(plain);
}
