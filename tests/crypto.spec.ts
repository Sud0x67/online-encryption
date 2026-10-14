import { describe, expect, it } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import { runCrypto } from '../src/app/crypto/engine';
import { decode, encode, pkcs7Unpad } from '../src/app/crypto/encoding';
import { defaults } from '../src/app/crypto/registry';
import { generateRsa } from '../src/app/crypto/rsa';
import { generateSm2 } from '../src/app/crypto/sm2';
import { AlgorithmId, Parameters, Mode, Hash } from '../src/app/crypto/types';
import fixtures from './fixtures/openssl.json' with { type: 'json' };
const run = (algorithm: AlgorithmId, params: Partial<Parameters> = {}) =>
  runCrypto({ algorithm, params: { ...defaults(algorithm), ...params } });
const fixed = {
  inputEncoding: 'hex',
  outputEncoding: 'hex',
  keyEncoding: 'hex',
  ivEncoding: 'hex',
  padding: 'none',
} as const;
describe('byte codecs', () => {
  it.each(['', '你好 🔐', 'abc\n\t', 'a\0b'])('round trips UTF-8 %j', (value) => {
    for (const format of ['hex', 'base64', 'utf8'] as const)
      expect(encode(decode(encode(decode(value, 'utf8'), format), format), 'utf8')).toBe(value);
  });
  it.each(['f', 'zz', '0x12'])('rejects invalid hex %s', (value) =>
    expect(() => decode(value, 'hex')).toThrow(),
  );
  it.each(['Zg', 'Zh==', 'Zg=', '***=', 'AA-_'])(
    'rejects malformed or noncanonical Base64 %s',
    (value) => expect(() => decode(value, 'base64')).toThrow(),
  );
  it('allows whitespace in byte encodings', () =>
    expect(encode(decode('00 ff\n10', 'hex'), 'hex')).toBe('00ff10'));
  it('rejects non-UTF8 result', () =>
    expect(() => encode(new Uint8Array([255]), 'utf8')).toThrow('UTF-8'));
  it('validates every padding byte', () =>
    expect(() => pkcs7Unpad(new Uint8Array([0, 0, 0, 0, 0, 0, 3, 2]), 8)).toThrow('填充'));
});
describe('published test vectors', () => {
  it.each([
    { key: '000102030405060708090a0b0c0d0e0f', cipher: '69c4e0d86a7b0430d8cdb78070b4c55a' },
    {
      key: '000102030405060708090a0b0c0d0e0f1011121314151617',
      cipher: 'dda97ca4864cdfe06eaf70a0ec0d7191',
    },
    {
      key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      cipher: '8ea2b7ca516745bfeafc49904b496089',
    },
  ])('FIPS 197 AES ECB $key', async (v) =>
    expect(
      (
        await run('aes', {
          ...fixed,
          mode: 'ECB',
          key: v.key,
          input: '00112233445566778899aabbccddeeff',
        })
      ).output,
    ).toBe(v.cipher),
  );
  it('NIST AES GCM', async () => {
    const p = {
      ...fixed,
      mode: 'GCM' as const,
      key: '00'.repeat(16),
      iv: '00'.repeat(12),
      input: '00'.repeat(16),
      tagEncoding: 'hex' as const,
    };
    const r = await run('aes', p);
    expect(r.output).toBe('0388dace60b6a392f328c2b971b2fe78');
    expect(r.tag).toBe('ab6e47d42cec13bdf53a67b21257bddf');
    expect(
      (await run('aes', { ...p, operation: 'decrypt', input: r.output, tag: r.tag })).output,
    ).toBe(p.input);
  });
  it('NIST AES CTR', async () =>
    expect(
      (
        await run('aes', {
          ...fixed,
          mode: 'CTR',
          key: '2b7e151628aed2a6abf7158809cf4f3c',
          iv: 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
          input: '6bc1bee22e409f96e93d7e117393172a',
        })
      ).output,
    ).toBe('874d6191b620e3261bef6864990db6ce'));
  it('NIST AES CBC without padding', async () =>
    expect(
      (
        await run('aes', {
          ...fixed,
          mode: 'CBC',
          key: '2b7e151628aed2a6abf7158809cf4f3c',
          iv: '000102030405060708090a0b0c0d0e0f',
          input: '6bc1bee22e409f96e93d7e117393172a',
        })
      ).output,
    ).toBe('7649abac8119b246cee98e9b12e9197d'));
  it('DES known answer', async () =>
    expect(
      (
        await run('des', {
          ...fixed,
          mode: 'ECB',
          key: '133457799bbcdff1',
          input: '0123456789abcdef',
        })
      ).output,
    ).toBe('85e813540f0ab405'));
  it('GM/T SM4 known answer', async () =>
    expect(
      (
        await run('sm4', {
          ...fixed,
          mode: 'ECB',
          key: '0123456789abcdeffedcba9876543210',
          input: '0123456789abcdeffedcba9876543210',
        })
      ).output,
    ).toBe('681edf34d206965e86b3e94f536e4246'));
  it('GM/T SM3 abc', async () =>
    expect((await run('sm3', { input: 'abc' })).output).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    ));
  it('RFC 4231 HMAC-SHA256', async () =>
    expect((await run('hmac', { input: 'Hi There', key: '0b'.repeat(20) })).output).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    ));
});
describe('OpenSSL fixtures: independent interoperability', () => {
  it.each(fixtures.symmetric)('$id $mode key $key', async (v) => {
    const p = { ...fixed, key: v.key, iv: v.iv, mode: v.mode as Mode, padding: 'pkcs7' as const };
    expect(
      (await run(v.id as AlgorithmId, { ...p, inputEncoding: 'utf8', input: v.plaintext })).output,
    ).toBe(v.ciphertext);
    expect(
      (
        await run(v.id as AlgorithmId, {
          ...p,
          operation: 'decrypt',
          input: v.ciphertext,
          outputEncoding: 'utf8',
        })
      ).output,
    ).toBe(v.plaintext);
  });
  it.each(['oaep-sha1', 'oaep-sha256', 'pkcs1'] as const)(
    'RSA %s both PEM families',
    async (variant) => {
      for (const privateKey of [fixtures.rsa.privateKey, fixtures.rsa.pkcs1PrivateKey])
        expect(
          (
            await run('rsa', {
              operation: 'decrypt',
              inputEncoding: 'hex',
              outputEncoding: 'utf8',
              input: fixtures.rsa[variant],
              privateKey,
              rsaScheme: variant === 'pkcs1' ? 'PKCS1' : 'OAEP',
              hash: variant === 'oaep-sha1' ? 'SHA-1' : 'SHA-256',
            })
          ).output,
        ).toBe(fixtures.rsa.plaintext);
    },
  );
  it.each(['C1C3C2', 'C1C2C3'] as const)('SM2 %s with/without prefix', async (order) => {
    for (const prefix of [true, false]) {
      const input = order === 'C1C3C2' ? fixtures.sm2.c1c3c2 : fixtures.sm2.c1c2c3;
      expect(
        (
          await run('sm2', {
            operation: 'decrypt',
            inputEncoding: 'hex',
            outputEncoding: 'utf8',
            input: prefix ? input : input.slice(2),
            privateKey: fixtures.sm2.privateKey,
            sm2Order: order,
            c1Prefix: prefix,
          })
        ).output,
      ).toBe(fixtures.sm2.plaintext);
    }
  });
});
describe('binary, Unicode and empty data', () => {
  it.each(['aes', 'des', '3des', 'sm4'] as const)('%s all block modes PKCS#7', async (id) => {
    for (const mode of ['CBC', 'ECB'] as const)
      for (const input of ['', '你好 🔐', 'a\0b']) {
        const p = {
          mode,
          key: '01'.repeat(id === 'des' ? 8 : id === '3des' ? 24 : 16),
          iv: '02'.repeat(id === 'des' || id === '3des' ? 8 : 16),
          outputEncoding: 'hex' as const,
        };
        const r = await run(id, { ...p, input });
        expect(
          (
            await run(id, {
              ...p,
              operation: 'decrypt',
              input: r.output,
              inputEncoding: 'hex',
              outputEncoding: 'utf8',
            })
          ).output,
        ).toBe(input);
      }
  });
  it.each(['GCM', 'CTR'] as const)('AES %s empty and AAD', async (mode) => {
    const p = {
      mode,
      key: '11'.repeat(16),
      iv: '22'.repeat(mode === 'GCM' ? 12 : 16),
      aad: '中文 AAD',
      outputEncoding: 'hex' as const,
    };
    for (const input of ['', '你好 🔐']) {
      const r = await run('aes', { ...p, input });
      expect(
        (
          await run('aes', {
            ...p,
            operation: 'decrypt',
            input: r.output,
            inputEncoding: 'hex',
            outputEncoding: 'utf8',
            tag: r.tag ?? '',
          })
        ).output,
      ).toBe(input);
    }
  });
  it.each(['md5', 'sha1', 'sha256', 'sha384', 'sha512'] as const)(
    '%s matches Node/OpenSSL digest',
    async (id) => {
      for (const input of ['', 'abc', '中文 🔐'])
        expect((await run(id, { input })).output).toBe(createHash(id).update(input).digest('hex'));
    },
  );
  it.each(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as Hash[])(
    'HMAC %s matches Node/OpenSSL',
    async (hash) =>
      expect(
        (await run('hmac', { hash, key: '秘密', keyEncoding: 'utf8', input: '你好 🔐' })).output,
      ).toBe(
        createHmac(hash.replace('-', '').toLowerCase(), '秘密').update('你好 🔐').digest('hex'),
      ),
  );
  it.each(['C1C3C2', 'C1C2C3'] as const)('SM2 %s supports empty and Unicode', async (sm2Order) => {
    for (const input of ['', '中文 🔐']) {
      const p = {
        publicKey: fixtures.sm2.publicKey,
        privateKey: fixtures.sm2.privateKey,
        sm2Order,
        outputEncoding: 'hex' as const,
      };
      const r = await run('sm2', { ...p, input });
      expect(
        (
          await run('sm2', {
            ...p,
            operation: 'decrypt',
            input: r.output,
            inputEncoding: 'hex',
            outputEncoding: 'utf8',
          })
        ).output,
      ).toBe(input);
    }
  });
  it('encoding conversion', async () =>
    expect(
      (
        await run('encoding', {
          input: '5L2g5aW9IPCflJA=',
          inputEncoding: 'base64',
          outputEncoding: 'utf8',
        })
      ).output,
    ).toBe('你好 🔐'));
  it.each([2048, 3072, 4096])('RSA generates %i bits and exports both formats', async (bits) => {
    const pair = await generateRsa(bits, bits === 3072 ? 'pkcs1' : 'standard');
    const p = { ...pair, input: '中文 🔐' };
    const r = await run('rsa', p);
    expect(
      (
        await run('rsa', {
          ...p,
          operation: 'decrypt',
          input: r.output,
          inputEncoding: 'base64',
          outputEncoding: 'utf8',
        })
      ).output,
    ).toBe(p.input);
    expect(r.bytes).toBe(bits / 8);
  });
  it('RSA imports PKCS1 public key for empty input and v1.5', async () => {
    for (const rsaScheme of ['OAEP', 'PKCS1'] as const) {
      const p = {
        publicKey: fixtures.rsa.pkcs1PublicKey,
        privateKey: fixtures.rsa.privateKey,
        rsaScheme,
      };
      const r = await run('rsa', p);
      expect(
        (
          await run('rsa', {
            ...p,
            operation: 'decrypt',
            input: r.output,
            inputEncoding: 'base64',
            outputEncoding: 'utf8',
          })
        ).output,
      ).toBe('');
    }
  });
  it('SM2 generates usable keys', async () => {
    const pair = await generateSm2();
    const r = await run('sm2', { ...pair, input: 'test' });
    expect(
      (
        await run('sm2', {
          ...pair,
          operation: 'decrypt',
          input: r.output,
          inputEncoding: 'base64',
          outputEncoding: 'utf8',
        })
      ).output,
    ).toBe('test');
  });
});
describe('validation and authentication failures', () => {
  it.each(['key', 'iv', 'aad', 'tag', 'input'] as const)('GCM tampered %s fails', async (field) => {
    const p = {
      key: '00'.repeat(16),
      iv: '00'.repeat(12),
      aad: 'AAD',
      input: 'test',
      outputEncoding: 'hex' as const,
      tagEncoding: 'hex' as const,
    };
    const r = await run('aes', p);
    const decrypt = {
      ...p,
      input: r.output,
      tag: r.tag!,
      operation: 'decrypt' as const,
      inputEncoding: 'hex' as const,
    };
    decrypt[field] =
      field === 'aad'
        ? 'BAD'
        : field === 'key'
          ? '11'.repeat(16)
          : field === 'iv'
            ? '11'.repeat(12)
            : 'ff' + decrypt[field].slice(2);
    await expect(run('aes', decrypt)).rejects.toThrow('认证失败');
  });
  it('SM2 altered C3 fails for nonempty and empty messages', async () => {
    for (const input of ['', 'test']) {
      const r = await run('sm2', {
        publicKey: fixtures.sm2.publicKey,
        input,
        outputEncoding: 'hex',
      });
      const cipher =
        r.output.slice(0, 130) +
        (r.output.slice(130, 132) === 'ff' ? '00' : 'ff') +
        r.output.slice(132);
      await expect(
        run('sm2', {
          operation: 'decrypt',
          inputEncoding: 'hex',
          input: cipher,
          privateKey: fixtures.sm2.privateKey,
        }),
      ).rejects.toThrow('完整性');
    }
  });
  it.each(['aes', 'des', '3des', 'sm4'] as const)(
    '%s rejects wrong key length and partial blocks',
    async (id) => {
      await expect(run(id, { key: '00' })).rejects.toThrow('密钥');
      await expect(
        run(id, {
          mode: 'ECB',
          key: '00'.repeat(id === 'des' ? 8 : id === '3des' ? 24 : 16),
          input: 'a',
          padding: 'none',
        }),
      ).rejects.toThrow('整数倍');
    },
  );
  it('RSA rejects oversized input', async () =>
    await expect(
      run('rsa', { publicKey: fixtures.rsa.publicKey, input: 'x'.repeat(191) }),
    ).rejects.toThrow('190 字节'));
  it('RSA rejects invalid PEM', async () =>
    await expect(run('rsa', { publicKey: 'invalid' })).rejects.toThrow('PEM'));
  it('RSA rejects wrong OAEP hash', async () =>
    await expect(
      run('rsa', {
        privateKey: fixtures.rsa.privateKey,
        input: fixtures.rsa['oaep-sha256'],
        inputEncoding: 'hex',
        operation: 'decrypt',
        hash: 'SHA-1',
      }),
    ).rejects.toThrow('RSA 加解密失败'));
  it('GCM rejects short tag', async () =>
    await expect(
      run('aes', { key: '00'.repeat(16), iv: '00'.repeat(12), operation: 'decrypt', tag: 'AA==' }),
    ).rejects.toThrow('16 字节'));
  it('HMAC rejects empty key', async () => await expect(run('hmac')).rejects.toThrow('不能为空'));
  it('SM2 rejects invalid point/private key/prefix', async () => {
    await expect(run('sm2', { publicKey: '04' + '00'.repeat(64) })).rejects.toThrow('公钥');
    await expect(run('sm2', { operation: 'decrypt', privateKey: '00'.repeat(32) })).rejects.toThrow(
      '私钥',
    );
    await expect(
      run('sm2', {
        operation: 'decrypt',
        privateKey: fixtures.sm2.privateKey,
        inputEncoding: 'hex',
        input: fixtures.sm2.c1c3c2.slice(2),
      }),
    ).rejects.toThrow('前缀');
  });
  it('rejects unsupported mode', async () =>
    await expect(run('des', { mode: 'GCM' })).rejects.toThrow('不支持'));
  it('strict PKCS7 decryption rejects modified padding', async () => {
    const r = await run('sm4', {
      key: '00'.repeat(16),
      mode: 'ECB',
      input: '00'.repeat(14) + '0302',
      ...fixed,
    });
    await expect(
      run('sm4', {
        ...fixed,
        key: '00'.repeat(16),
        mode: 'ECB',
        padding: 'pkcs7',
        operation: 'decrypt',
        input: r.output,
      }),
    ).rejects.toThrow('填充');
  });
});
