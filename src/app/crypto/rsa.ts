import type * as Forge from 'node-forge';
import { buffer, encode } from './encoding';
import { KeyPair, Parameters } from './types';
export async function generateRsa(bits: number, format: 'standard' | 'pkcs1'): Promise<KeyPair> {
  if (![2048, 3072, 4096].includes(bits)) throw new Error('RSA 位数必须为 2048、3072 或 4096。');
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const { default: forge } = await import('node-forge');
  const pub = forge.pki.publicKeyFromAsn1(
    forge.asn1.fromDer(
      forge.util.createBuffer(
        new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
      ),
    ),
  );
  const priv = forge.pki.privateKeyFromAsn1(
    forge.asn1.fromDer(
      forge.util.createBuffer(
        new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
      ),
    ),
  );
  return {
    publicKey:
      format === 'pkcs1'
        ? forge.pki.publicKeyToRSAPublicKeyPem(pub)
        : forge.pki.publicKeyToPem(pub),
    privateKey:
      format === 'pkcs1'
        ? forge.pki.privateKeyToPem(priv)
        : forge.pki.privateKeyInfoToPem(
            forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(priv)),
          ),
  };
}
export async function rsa(p: Parameters, input: Uint8Array): Promise<Uint8Array> {
  const encrypt = p.operation === 'encrypt';
  const { default: forge } = await import('node-forge');
  const pem = encrypt ? p.publicKey : p.privateKey;
  if (/ENCRYPTED|Proc-Type:/.test(pem)) throw new Error('首版仅支持未加密 PEM 密钥。');
  let key: Forge.pki.rsa.PublicKey | Forge.pki.rsa.PrivateKey;
  try {
    key = encrypt ? forge.pki.publicKeyFromPem(pem) : forge.pki.privateKeyFromPem(pem);
  } catch {
    throw new Error(
      encrypt
        ? '公钥 PEM 无效，支持 SPKI / PKCS#1。'
        : '私钥 PEM 无效，支持未加密 PKCS#8 / PKCS#1。',
    );
  }
  const size = Math.ceil(key.n.bitLength() / 8);
  const limit = size - (p.rsaScheme === 'PKCS1' ? 11 : 2 * (p.hash === 'SHA-1' ? 20 : 32) + 2);
  if (encrypt && input.length > limit)
    throw new Error(`RSA 明文最多 ${limit} 字节，当前 ${input.length} 字节；不支持自动分段。`);
  if (!encrypt && input.length !== size) throw new Error(`RSA 密文必须为 ${size} 字节。`);
  try {
    if (p.rsaScheme === 'OAEP') {
      const der = encrypt
        ? forge.asn1.toDer(forge.pki.publicKeyToAsn1(key as Forge.pki.rsa.PublicKey)).getBytes()
        : forge.asn1
            .toDer(
              forge.pki.wrapRsaPrivateKey(
                forge.pki.privateKeyToAsn1(key as Forge.pki.rsa.PrivateKey),
              ),
            )
            .getBytes();
      const bytes = Uint8Array.from(der, (ch) => ch.charCodeAt(0));
      const imported = await crypto.subtle.importKey(
        encrypt ? 'spki' : 'pkcs8',
        buffer(bytes),
        { name: 'RSA-OAEP', hash: p.hash },
        false,
        [encrypt ? 'encrypt' : 'decrypt'],
      );
      return new Uint8Array(
        await crypto.subtle[encrypt ? 'encrypt' : 'decrypt'](
          { name: 'RSA-OAEP' },
          imported,
          buffer(input),
        ),
      );
    }
    const binary = forge.util.hexToBytes(encode(input, 'hex'));
    const result = encrypt
      ? (key as Forge.pki.rsa.PublicKey).encrypt(binary, 'RSAES-PKCS1-V1_5')
      : (key as Forge.pki.rsa.PrivateKey).decrypt(binary, 'RSAES-PKCS1-V1_5');
    return Uint8Array.from(result, (ch) => ch.charCodeAt(0));
  } catch {
    throw new Error('RSA 加解密失败，请检查密钥、填充方式、OAEP 摘要和密文。');
  }
}
