import { AlgorithmId } from '../crypto/types';
import { ALGORITHM_GUIDES, AlgorithmGuide } from './algorithm-guides';
const sourceLabels: Record<string, string> = {
  'NIST · GCM 模式': 'NIST · GCM mode',
  'NIST · DES / TDEA 使用状态': 'NIST · DES / TDEA status',
  'RFC 8998 · 国密算法概览': 'RFC 8998 · SM algorithm overview',
  'RFC 8017 · RSA 加密规范': 'RFC 8017 · RSA encryption specification',
  'sm-crypto · SM2 格式约定': 'sm-crypto · SM2 formats',
  'RFC 6151 · MD5 安全性说明': 'RFC 6151 · MD5 security considerations',
  'NIST · SHA-1 迁移说明': 'NIST · SHA-1 transition',
};
const sources = (id: AlgorithmId) =>
  ALGORITHM_GUIDES[id].sources.map((source) => ({
    ...source,
    label: sourceLabels[source.label] ?? source.label,
  }));
const digestNotes = [
  'A digest cannot be decrypted and does not authenticate the source by itself. Use HMAC or a digital signature to authenticate a message.',
  'Fast general-purpose hashes should not be used directly for password storage. Use a dedicated password-hashing scheme.',
  'Normalize encoding, whitespace and line endings before comparison. Hashes operate on bytes, not visually identical text.',
];
export const ENGLISH_ALGORITHM_GUIDES: Record<AlgorithmId, AlgorithmGuide> = {
  aes: {
    summary:
      'AES is a widely used symmetric block cipher. Encryption and decryption use the same secret key.',
    facts: [
      { label: 'Key size', value: '128 / 192 / 256 bits' },
      { label: 'Block size', value: '128 bits (16 bytes)' },
      { label: 'Supported modes', value: 'GCM / CBC / CTR / ECB' },
    ],
    principle:
      'AES transforms each block through multiple rounds. The mode determines how blocks, IVs and authentication are handled. Key size and block size are different parameters.',
    uses: 'Protect application data and message content. This tool defaults to AES-GCM, which provides both encryption and integrity authentication.',
    notes: [
      'Never reuse a GCM IV with the same key. AAD is authenticated but is not encrypted.',
      'CBC, CTR and ECB do not provide authentication by themselves. ECB also reveals repeated blocks.',
      'Both sides must agree on CBC / ECB padding. GCM / CTR do not require padding.',
    ],
    sources: sources('aes'),
  },
  des: {
    summary:
      'DES is an early symmetric block cipher, retained here for legacy compatibility and debugging.',
    facts: [
      { label: 'Key input', value: '64 bits (including parity)' },
      { label: 'Effective key size', value: '56 bits' },
      { label: 'Block size', value: '64 bits (8 bytes)' },
    ],
    principle:
      'DES uses a Feistel structure to process blocks over multiple rounds. Its 8-byte key includes parity bits, so its effective key size is not 64 bits.',
    uses: 'Read historical ciphertext, reproduce legacy interfaces and check existing parameter conventions. This tool supports CBC and ECB.',
    notes: [
      'The DES key space is too small for new sensitive data. Prefer a modern algorithm such as AES for new designs.',
      'CBC requires an 8-byte IV. Without padding, the input length must be a multiple of 8 bytes.',
    ],
    sources: sources('des'),
  },
  '3des': {
    summary:
      '3DES (TDEA) combines three DES operations to extend the usefulness of older DES systems.',
    facts: [
      { label: 'Supported key input', value: '24 bytes (three DES keys)' },
      { label: 'Block size', value: '64 bits (8 bytes)' },
      { label: 'Supported modes', value: 'CBC / ECB' },
    ],
    principle:
      'The common construction is encrypt–decrypt–encrypt (EDE). DES parity bits are included in the key input; a 24-byte key does not imply 192-bit security.',
    uses: 'Debug legacy business protocols and historical ciphertext. Use modern encryption for new systems.',
    notes: [
      'Its performance and 64-bit block size make 3DES unsuitable for modern bulk encryption. NIST has withdrawn its TDEA recommendation.',
      'This tool requires a 24-byte raw key and does not automatically extend 16-byte keys.',
    ],
    sources: sources('3des'),
  },
  sm4: {
    summary:
      'SM4 is a symmetric block cipher in the Chinese SM algorithm family. Both its key and block sizes are 128 bits.',
    facts: [
      { label: 'Key size', value: '128 bits (16 bytes)' },
      { label: 'Block size', value: '128 bits (16 bytes)' },
      { label: 'Supported modes', value: 'CBC / ECB' },
    ],
    principle:
      'SM4 applies multiple rounds of transformation using a fixed-size key. Like other block ciphers, it requires an agreed mode and padding convention.',
    uses: 'Work with systems using SM protocols and debug their key, IV, padding and encoding conventions.',
    notes: [
      'SM4 encryption and SM3 hashing serve different purposes and are not interchangeable.',
      'The supported CBC / ECB modes do not include authentication. The surrounding protocol must provide it separately.',
    ],
    sources: sources('sm4'),
  },
  rsa: {
    summary:
      'RSA is an asymmetric algorithm: encrypt with a public key and decrypt with the matching private key.',
    facts: [
      { label: 'Generated key sizes', value: '2048 / 3072 / 4096 bits' },
      { label: 'Encryption schemes', value: 'OAEP / PKCS#1 v1.5' },
      { label: 'Key format', value: 'PEM (SPKI / PKCS#8 / PKCS#1)' },
    ],
    principle:
      'RSA uses mathematically related public and private keys. A padding scheme securely encodes the message. The key, OAEP hash and MGF1 hash must match the other implementation.',
    uses: 'Encrypt short messages or wrap symmetric keys. Large data is typically protected with hybrid encryption: encrypt it with AES and protect the AES key with RSA.',
    notes: [
      'RSA key size describes the modulus length. It is not directly comparable to AES key size as a measure of security.',
      '2048-bit RSA with OAEP-SHA256 accepts at most 190 bytes. This tool does not automatically split messages.',
      'Prefer OAEP for new designs. PEM is a key representation, not a cipher mode; encrypted PEM is not supported here.',
    ],
    sources: sources('rsa'),
  },
  sm2: {
    summary:
      'SM2 is an elliptic-curve public-key algorithm family. This tool implements its public-key encryption and decryption operations.',
    facts: [
      { label: 'Curve', value: '256-bit SM2 curve' },
      { label: 'Private key input', value: '32 bytes in Hex' },
      { label: 'Ciphertext order', value: 'C1C3C2 / C1C2C3' },
    ],
    principle:
      'Encryption uses the recipient’s public key and an ephemeral random value. C1 is an ephemeral curve point, C2 is encrypted message data and C3 is an integrity check. Decryption requires the matching private key.',
    uses: 'Exchange short messages and key material in SM systems. Raw point format helps debug ciphertext ordering differences between libraries.',
    notes: [
      '04 is the uncompressed-point prefix in public keys and ciphertext. It is not part of the private key. Match the ciphertext prefix setting with the other implementation.',
      'ASN.1 DER ciphertext is not accepted. SM2 encryption and SM2 signatures are separate operations.',
    ],
    sources: sources('sm2'),
  },
  md5: {
    summary: 'MD5 produces a 128-bit message digest. It is not reversible encryption.',
    facts: [
      { label: 'Digest size', value: '128 bits (16 bytes)' },
      { label: 'Hex length', value: '32 characters' },
      { label: 'Key', value: 'Not required' },
    ],
    principle:
      'MD5 maps arbitrary input bytes to a fixed-length digest. Different inputs can have the same digest; practical collision attacks have broken its collision resistance.',
    uses: 'Compare historical checksums or debug legacy interfaces. Use a more appropriate scheme when malicious changes or trusted identity are relevant.',
    notes: [
      'MD5 cannot establish that a file has not been maliciously substituted and should not be used directly for password storage.',
      digestNotes[0],
      digestNotes[2],
    ],
    sources: sources('md5'),
  },
  sha1: {
    summary:
      'SHA-1 is a one-way hash with a 160-bit output, retained here for legacy compatibility.',
    facts: [
      { label: 'Digest size', value: '160 bits (20 bytes)' },
      { label: 'Hex length', value: '40 characters' },
      { label: 'Key', value: 'Not required' },
    ],
    principle:
      'SHA-1 processes input blocks into a fixed-length digest. Its collision resistance has been broken; do not use it for new collision-resistant designs.',
    uses: 'Compare historical digests and debug interfaces that still require SHA-1. SHA-256 is a common choice for new general-purpose hashing.',
    notes: digestNotes,
    sources: sources('sha1'),
  },
  sha256: {
    summary:
      'SHA-256 belongs to the SHA-2 family and produces a 256-bit digest. It is a common general-purpose hash.',
    facts: [
      { label: 'Digest size', value: '256 bits (32 bytes)' },
      { label: 'Hex length', value: '64 characters' },
      { label: 'Key', value: 'Not required' },
    ],
    principle:
      'SHA-256 compresses variable-length input into a fixed-length digest. Identical bytes produce identical results; an input change typically changes the entire digest.',
    uses: 'Create data fingerprints, file digests and protocol test values. Use HMAC-SHA256 with a shared secret when the message source must be authenticated.',
    notes: digestNotes,
    sources: sources('sha256'),
  },
  sha384: {
    summary:
      'SHA-384 belongs to the SHA-2 family and produces a 384-bit digest, longer than SHA-256.',
    facts: [
      { label: 'Digest size', value: '384 bits (48 bytes)' },
      { label: 'Hex length', value: '96 characters' },
      { label: 'Key', value: 'Not required' },
    ],
    principle:
      'SHA-384 uses the SHA-512 processing structure with different initial values and a truncated result. It is not simply a truncation of ordinary SHA-512 output.',
    uses: 'Use it for protocols, checksums and authentication values that specifically require SHA-384. Follow the other implementation’s hash convention.',
    notes: digestNotes,
    sources: sources('sha384'),
  },
  sha512: {
    summary:
      'SHA-512 belongs to the SHA-2 family and produces a 512-bit digest for protocols requiring a longer hash.',
    facts: [
      { label: 'Digest size', value: '512 bits (64 bytes)' },
      { label: 'Hex length', value: '128 characters' },
      { label: 'Key', value: 'Not required' },
    ],
    principle:
      'SHA-512 uses 64-bit word operations to process input blocks into a fixed-length digest. A longer digest is not necessary for every application.',
    uses: 'Compute specified SHA-512 checksums or use it within HMAC. Matching the protocol is more important than choosing the longest output.',
    notes: digestNotes,
    sources: sources('sha512'),
  },
  sm3: {
    summary:
      'SM3 is a message-digest algorithm in the Chinese SM family. It produces 256 bits and has no decryption operation.',
    facts: [
      { label: 'Digest size', value: '256 bits (32 bytes)' },
      { label: 'Hex length', value: '64 characters' },
      { label: 'Key', value: 'Not required' },
    ],
    principle:
      'SM3 compresses input bytes over multiple rounds. Its output size matches SHA-256, but the algorithms and their results are different.',
    uses: 'Compute digests and checksums in SM protocols. SM2 and other protocols also use SM3 as a component.',
    notes: digestNotes,
    sources: sources('sm3'),
  },
  hmac: {
    summary:
      'HMAC combines a shared secret with a hash to produce a message authentication value that checks integrity and source.',
    facts: [
      { label: 'Supported hashes', value: 'SHA-1 / 256 / 384 / 512' },
      { label: 'Key', value: 'Shared raw bytes' },
      { label: 'Output size', value: 'Matches the selected hash digest' },
    ],
    principle:
      'HMAC processes the key and message with a defined inner and outer hash structure. It is not equivalent to concatenating the key with the message and hashing it.',
    uses: 'Authenticate protocols and check request integrity. A party holding the same key can recalculate and compare the authentication value.',
    notes: [
      'HMAC does not hide message content and has no decryption operation. Use encryption when confidentiality is needed.',
      'Anyone holding the shared key can generate authentication values. HMAC is not a public-key digital signature.',
      'HMAC alone does not prevent replay. Protocols also need timestamps, nonces or sequence numbers.',
    ],
    sources: sources('hmac'),
  },
  encoding: {
    summary:
      'UTF-8, Hex and Base64 are data representations. Encoding conversion is reversible and does not provide encryption.',
    facts: [
      { label: 'UTF-8', value: 'Encodes text as bytes' },
      { label: 'Hex', value: '2 characters per byte' },
      { label: 'Base64', value: '4 characters per group of up to 3 bytes' },
    ],
    principle:
      'Decode the input into bytes, then express those same bytes in the output encoding. UTF-8 represents text; Hex and Base64 can represent arbitrary binary data.',
    uses: 'Transfer keys, IVs, ciphertext and digests, or check text and byte conventions between programs.',
    notes: [
      'This tool accepts standard Base64 with the + / alphabet and = padding, not Base64URL.',
      'Not every byte sequence is valid UTF-8. Use Hex or Base64 for those outputs.',
      'Unicode characters, emoji and line endings affect UTF-8 byte length. Character count is not byte count.',
    ],
    sources: sources('encoding'),
  },
};
