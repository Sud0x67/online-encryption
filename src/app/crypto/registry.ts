import { Algorithm, AlgorithmId, Parameters } from './types';
export const ALGORITHMS: readonly Algorithm[] = [
  {
    id: 'aes',
    title: 'AES',
    subtitle: '高级加密标准',
    group: '对称加密',
    category: 'symmetric',
    modes: ['GCM', 'CBC', 'CTR', 'ECB'],
  },
  {
    id: 'des',
    title: 'DES',
    subtitle: '传统分组加密',
    group: '对称加密',
    category: 'symmetric',
    modes: ['CBC', 'ECB'],
    badge: '兼容',
  },
  {
    id: '3des',
    title: '3DES',
    subtitle: '三重 DES',
    group: '对称加密',
    category: 'symmetric',
    modes: ['CBC', 'ECB'],
    badge: '兼容',
  },
  {
    id: 'sm4',
    title: 'SM4',
    subtitle: '国密分组加密',
    group: '对称加密',
    category: 'symmetric',
    modes: ['CBC', 'ECB'],
    badge: '国密',
  },
  { id: 'rsa', title: 'RSA', subtitle: '公钥加密', group: '公钥加密', category: 'asymmetric' },
  {
    id: 'sm2',
    title: 'SM2',
    subtitle: '国密椭圆曲线',
    group: '公钥加密',
    category: 'asymmetric',
    badge: '国密',
  },
  {
    id: 'md5',
    title: 'MD5',
    subtitle: '128 位摘要',
    group: '消息摘要',
    category: 'digest',
    badge: '兼容',
  },
  {
    id: 'sha1',
    title: 'SHA-1',
    subtitle: '160 位摘要',
    group: '消息摘要',
    category: 'digest',
    badge: '兼容',
  },
  { id: 'sha256', title: 'SHA-256', subtitle: '256 位摘要', group: '消息摘要', category: 'digest' },
  { id: 'sha384', title: 'SHA-384', subtitle: '384 位摘要', group: '消息摘要', category: 'digest' },
  { id: 'sha512', title: 'SHA-512', subtitle: '512 位摘要', group: '消息摘要', category: 'digest' },
  {
    id: 'sm3',
    title: 'SM3',
    subtitle: '国密消息摘要',
    group: '消息摘要',
    category: 'digest',
    badge: '国密',
  },
  { id: 'hmac', title: 'HMAC', subtitle: '带密钥的消息认证', group: '消息认证', category: 'hmac' },
  {
    id: 'encoding',
    title: '编码转换',
    subtitle: 'UTF-8 / Hex / Base64',
    group: '编码转换',
    category: 'encoding',
  },
];
export function algorithmById(id: string | null): Algorithm {
  return ALGORITHMS.find((a) => a.id === id) ?? ALGORITHMS[0];
}
export function defaults(id: AlgorithmId): Parameters {
  const a = algorithmById(id);
  return {
    input: '',
    inputEncoding: 'utf8',
    outputEncoding: a.category === 'digest' || a.category === 'hmac' ? 'hex' : 'base64',
    operation:
      a.category === 'digest' || a.category === 'hmac' || a.category === 'encoding'
        ? 'compute'
        : 'encrypt',
    mode: id === 'aes' ? 'GCM' : 'CBC',
    padding: 'pkcs7',
    key: '',
    keyEncoding: 'hex',
    iv: '',
    ivEncoding: 'hex',
    aad: '',
    aadEncoding: 'utf8',
    tag: '',
    tagEncoding: 'base64',
    keySize: 256,
    rsaScheme: 'OAEP',
    hash: 'SHA-256',
    rsaBits: 2048,
    publicKey: '',
    privateKey: '',
    pemFormat: 'standard',
    sm2Order: 'C1C3C2',
    c1Prefix: true,
  };
}
