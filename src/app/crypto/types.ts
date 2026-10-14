export type Encoding = 'utf8' | 'hex' | 'base64';
export type AlgorithmId =
  | 'aes'
  | 'des'
  | '3des'
  | 'rsa'
  | 'sm2'
  | 'sm4'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'sha384'
  | 'sha512'
  | 'sm3'
  | 'hmac'
  | 'encoding';
export type Operation = 'encrypt' | 'decrypt' | 'compute';
export type Mode = 'GCM' | 'CBC' | 'CTR' | 'ECB';
export type Hash = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
export interface Parameters {
  input: string;
  inputEncoding: Encoding;
  outputEncoding: Encoding;
  operation: Operation;
  mode: Mode;
  padding: 'pkcs7' | 'none';
  key: string;
  keyEncoding: Encoding;
  iv: string;
  ivEncoding: Encoding;
  aad: string;
  aadEncoding: Encoding;
  tag: string;
  tagEncoding: Encoding;
  keySize: number;
  rsaScheme: 'OAEP' | 'PKCS1';
  hash: Hash;
  rsaBits: number;
  publicKey: string;
  privateKey: string;
  pemFormat: 'standard' | 'pkcs1';
  sm2Order: 'C1C3C2' | 'C1C2C3';
  c1Prefix: boolean;
}
export interface CryptoRequest {
  algorithm: AlgorithmId;
  params: Parameters;
}
export interface CryptoResult {
  output: string;
  tag?: string;
  bytes: number;
}
export interface KeyPair {
  publicKey: string;
  privateKey: string;
}
export type WorkerTask =
  | { action: 'run'; request: CryptoRequest }
  | { action: 'generate-rsa'; bits: number; format: 'standard' | 'pkcs1' }
  | { action: 'generate-sm2' };
export interface Algorithm {
  id: AlgorithmId;
  title: string;
  subtitle: string;
  group: string;
  category: 'symmetric' | 'asymmetric' | 'digest' | 'hmac' | 'encoding';
  modes?: Mode[];
  badge?: string;
}
