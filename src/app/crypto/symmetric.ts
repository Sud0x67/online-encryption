import type * as Forge from 'node-forge';
import { buffer, encode, pkcs7Pad, pkcs7Unpad } from './encoding';
import { AlgorithmId, Parameters } from './types';
export async function symmetric(
  id: AlgorithmId,
  p: Parameters,
  input: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  tag: Uint8Array,
): Promise<{ data: Uint8Array; tag?: Uint8Array }> {
  const encrypt = p.operation === 'encrypt';
  const blockSize = id === 'des' || id === '3des' ? 8 : 16;
  const allowed = id === 'aes' ? [16, 24, 32] : id === 'des' ? [8] : id === '3des' ? [24] : [16];
  if (!allowed.includes(key.length))
    throw new Error(
      `${id.toUpperCase()} 密钥必须为 ${allowed.join(' / ')} 字节（当前 ${key.length} 字节）。`,
    );
  if (p.mode !== 'ECB' && iv.length !== (p.mode === 'GCM' ? 12 : blockSize))
    throw new Error(`IV 必须为 ${p.mode === 'GCM' ? 12 : blockSize} 字节。`);
  if (
    p.mode === 'GCM' ||
    p.mode === 'CTR' ||
    (id === 'aes' && p.mode === 'CBC' && p.padding === 'pkcs7')
  ) {
    if (!encrypt && p.mode === 'GCM' && tag.length !== 16)
      throw new Error('GCM 认证标签必须为 16 字节。');
    const name = `AES-${p.mode}`;
    const algorithm =
      p.mode === 'GCM'
        ? { name, iv: buffer(iv), additionalData: buffer(aad), tagLength: 128 }
        : p.mode === 'CTR'
          ? { name, counter: buffer(iv), length: 128 }
          : { name, iv: buffer(iv) };
    const cryptoKey = await crypto.subtle.importKey('raw', buffer(key), { name }, false, [
      encrypt ? 'encrypt' : 'decrypt',
    ]);
    let payload = input;
    if (!encrypt && p.mode === 'GCM') {
      payload = new Uint8Array(input.length + tag.length);
      payload.set(input);
      payload.set(tag, input.length);
    }
    try {
      const result = new Uint8Array(
        await crypto.subtle[encrypt ? 'encrypt' : 'decrypt'](algorithm, cryptoKey, buffer(payload)),
      );
      return encrypt && p.mode === 'GCM'
        ? { data: result.slice(0, -16), tag: result.slice(-16) }
        : { data: result };
    } catch {
      throw new Error(
        p.mode === 'GCM'
          ? 'GCM 认证失败，请检查密钥、IV、AAD、认证标签和密文。'
          : '加解密失败，请检查密钥、IV、密文长度及填充。',
      );
    }
  }
  if (!encrypt && input.length % blockSize)
    throw new Error(`密文长度必须为 ${blockSize} 字节的整数倍。`);
  if (p.padding === 'none' && input.length % blockSize)
    throw new Error(`无填充模式要求输入长度为 ${blockSize} 字节的整数倍。`);
  const payload = encrypt && p.padding === 'pkcs7' ? pkcs7Pad(input, blockSize) : input;
  let data: Uint8Array;
  if (id === 'sm4') {
    const { sm4 } = (await import('sm-crypto')).default;
    const options = {
      padding: 'none',
      output: 'array',
      ...(p.mode === 'CBC' ? { mode: 'cbc', iv: Array.from(iv) } : {}),
    } as const;
    data = Uint8Array.from(
      encrypt
        ? sm4.encrypt(Array.from(payload), Array.from(key), options)
        : sm4.decrypt(Array.from(payload), Array.from(key), options),
    );
  } else {
    const { default: forge } = await import('node-forge');
    const binary = (bytes: Uint8Array) => forge.util.hexToBytes(encode(bytes, 'hex'));
    const name = `${id === 'aes' ? 'AES' : id === 'des' ? 'DES' : '3DES'}-${p.mode}`;
    const cipher = encrypt
      ? forge.cipher.createCipher(name as Forge.cipher.Algorithm, binary(key))
      : forge.cipher.createDecipher(name as Forge.cipher.Algorithm, binary(key));
    cipher.start({ iv: p.mode === 'ECB' ? undefined : binary(iv) });
    cipher.update(forge.util.createBuffer(binary(payload)));
    // Padding is handled here so every byte is validated, independent of library defaults.
    if (!(cipher.finish as (padding: () => boolean) => boolean)(() => true))
      throw new Error('分组加解密失败。');
    data = Uint8Array.from(cipher.output.getBytes(), (ch) => ch.charCodeAt(0));
  }
  return { data: !encrypt && p.padding === 'pkcs7' ? pkcs7Unpad(data, blockSize) : data };
}
