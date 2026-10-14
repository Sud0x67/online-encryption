declare module 'sm-crypto' {
  export const sm2: {
    generateKeyPairHex(): { publicKey: string; privateKey: string };
    verifyPublicKey(key: string): boolean;
    doEncrypt(data: number[], key: string, mode: number): string;
    doDecrypt(data: string, key: string, mode: number, options: { output: 'array' }): number[];
  };
  export function sm3(data: number[]): string;
  export const sm4: {
    encrypt(
      data: number[],
      key: number[],
      options: { padding: string; output: string; mode?: string; iv?: number[] },
    ): number[];
    decrypt(
      data: number[],
      key: number[],
      options: { padding: string; output: string; mode?: string; iv?: number[] },
    ): number[];
  };
  const sm: { sm2: typeof sm2; sm3: typeof sm3; sm4: typeof sm4 };
  export default sm;
}
declare module 'sm-crypto/src/sm2/utils.js' {
  import { BigInteger } from 'jsbn';
  interface Point {
    multiply(value: BigInteger): Point;
    getX(): { toBigInteger(): BigInteger };
    getY(): { toBigInteger(): BigInteger };
  }
  export function getGlobalCurve(): { decodePointHex(value: string): Point };
  const utils: { getGlobalCurve: typeof getGlobalCurve };
  export default utils;
}
