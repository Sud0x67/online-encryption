import { AlgorithmId } from '../crypto/types';

export interface AlgorithmGuide {
  summary: string;
  facts: { label: string; value: string }[];
  principle: string;
  uses: string;
  notes: string[];
  sources: { label: string; url: string }[];
}
const shaSource = {
  label: 'NIST · FIPS 180-4',
  url: 'https://csrc.nist.gov/pubs/fips/180-4/upd1/final',
};
const smSource = {
  label: 'RFC 8998 · 国密算法概览',
  url: 'https://www.rfc-editor.org/rfc/rfc8998.html#section-1.1',
};
const legacySource = {
  label: 'NIST · DES / TDEA 使用状态',
  url: 'https://csrc.nist.gov/News/2023/nist-to-withdraw-sp-800-67-rev-2',
};
const digestNotes = [
  '摘要不能解密，也不能单独证明数据来源；验证来源需要 HMAC 或数字签名。',
  '普通快速摘要不适合直接存储密码；密码存储需要专门的密码哈希方案。',
  '比较前统一文本编码、空格和换行，摘要针对字节而非视觉上相同的文字。',
];

export const ALGORITHM_GUIDES: Record<AlgorithmId, AlgorithmGuide> = {
  aes: {
    summary: 'AES 是现代系统中常用的对称分组加密算法，加密与解密使用同一把密钥。',
    facts: [
      { label: '密钥长度', value: '128 / 192 / 256 位' },
      { label: '分组长度', value: '128 位（16 字节）' },
      { label: '本站模式', value: 'GCM / CBC / CTR / ECB' },
    ],
    principle:
      'AES 对每个数据分组执行多轮变换。工作模式决定如何处理多个分组、IV 与认证；密钥长度和分组长度是两个不同的参数。',
    uses: '适合保护业务数据和消息内容。本站默认使用 AES-GCM，它同时提供内容加密与完整性认证。',
    notes: [
      'GCM 的 IV 在同一密钥下必须唯一；AAD 参与认证但不会被加密。',
      'CBC、CTR 与 ECB 本身不提供完整性认证；ECB 还会暴露重复分组。',
      'CBC / ECB 的填充规则需与对端一致；GCM / CTR 不需要填充。',
    ],
    sources: [
      { label: 'NIST · FIPS 197', url: 'https://csrc.nist.gov/pubs/fips/197/final' },
      { label: 'NIST · GCM 模式', url: 'https://csrc.nist.gov/pubs/sp/800/38/d/final' },
    ],
  },
  des: {
    summary: 'DES 是早期的对称分组加密算法，目前主要用于旧系统兼容与调试。',
    facts: [
      { label: '密钥输入', value: '64 位（含校验位）' },
      { label: '有效密钥', value: '56 位' },
      { label: '分组长度', value: '64 位（8 字节）' },
    ],
    principle:
      'DES 使用 Feistel 结构逐轮处理分组。它的 8 字节密钥中包含校验位，有效密钥长度并不是 64 位。',
    uses: '用于读取历史密文、复现旧接口和检查既有系统的参数约定。本站提供 CBC 与 ECB。',
    notes: [
      'DES 的密钥空间过小，不适合保护新的敏感数据；新设计优先采用 AES 等现代方案。',
      'CBC 的 IV 为 8 字节；无填充时输入长度必须为 8 字节的整数倍。',
    ],
    sources: [legacySource],
  },
  '3des': {
    summary: '3DES（TDEA）通过组合三次 DES 运算延长旧 DES 系统的使用寿命。',
    facts: [
      { label: '本站密钥', value: '24 字节（三把 DES 密钥）' },
      { label: '分组长度', value: '64 位（8 字节）' },
      { label: '本站模式', value: 'CBC / ECB' },
    ],
    principle:
      '常用结构是加密—解密—加密（EDE）。密钥输入包含 DES 校验位，24 字节输入不能被视作 192 位安全强度。',
    uses: '用于旧业务协议与历史密文的兼容调试。新系统应使用现代加密方案。',
    notes: [
      '3DES 的处理速度与 64 位分组限制不适合现代大量数据加密；NIST 已撤回相关 TDEA 推荐标准。',
      '本站仅接受 24 字节原始密钥，不会把 16 字节密钥自动扩展为三密钥格式。',
    ],
    sources: [legacySource],
  },
  sm4: {
    summary: 'SM4 是国密对称分组加密算法，密钥和分组长度均为 128 位。',
    facts: [
      { label: '密钥长度', value: '128 位（16 字节）' },
      { label: '分组长度', value: '128 位（16 字节）' },
      { label: '本站模式', value: 'CBC / ECB' },
    ],
    principle:
      'SM4 使用固定长度的密钥对分组进行多轮变换。与其他分组算法一样，实际使用还需要约定工作模式和填充。',
    uses: '用于使用国密协议的系统，尤其适合调试双方的密钥、IV、填充与编码约定。',
    notes: [
      'SM4 加密与 SM3 摘要承担不同任务，不能互相替代。',
      '本站 CBC / ECB 模式不附带完整性认证；需要由协议另外设计认证机制。',
    ],
    sources: [smSource],
  },
  rsa: {
    summary: 'RSA 是非对称算法：使用公钥加密，持有对应私钥的一方才能解密。',
    facts: [
      { label: '本站密钥生成', value: '2048 / 3072 / 4096 位' },
      { label: '加密方案', value: 'OAEP / PKCS#1 v1.5' },
      { label: '密钥格式', value: 'PEM（SPKI / PKCS#8 / PKCS#1）' },
    ],
    principle:
      'RSA 使用一对数学上相关的公私钥，并通过填充方案安全地编码消息。OAEP 的摘要、MGF1 摘要和密钥必须与对端一致。',
    uses: '适合加密短消息或封装对称密钥。较大的数据通常采用混合加密：用 AES 加密数据，再用 RSA 保护 AES 密钥。',
    notes: [
      'RSA 密钥的位数指模数长度，不能直接与 AES 的密钥位数比较安全强度。',
      '2048 位 RSA 配合 OAEP-SHA256 最多加密 190 字节；本站不自动分段。',
      '新设计优先选择 OAEP。PEM 是密钥表示格式，不是加密模式；本站不支持加密 PEM。',
    ],
    sources: [
      { label: 'RFC 8017 · RSA 加密规范', url: 'https://www.rfc-editor.org/rfc/rfc8017.html' },
    ],
  },
  sm2: {
    summary: 'SM2 是基于椭圆曲线的国密公钥算法体系，本站提供其中的公钥加解密功能。',
    facts: [
      { label: '曲线', value: '256 位 SM2 曲线' },
      { label: '私钥输入', value: '32 字节 Hex' },
      { label: '密文排列', value: 'C1C3C2 / C1C2C3' },
    ],
    principle:
      '加密使用接收方公钥与临时随机数。C1 表示临时曲线点，C2 是加密后的消息，C3 用于完整性校验；解密需要对应私钥。',
    uses: '用于国密系统的短消息与密钥材料交换。本站使用原始点格式，便于检查不同库之间的密文排列差异。',
    notes: [
      '公钥和密文中的 04 是未压缩点的格式前缀，不是私钥的一部分；密文前缀选项需与对端一致。',
      '本站不接收 ASN.1 DER 密文；SM2 加解密和 SM2 签名是不同功能。',
    ],
    sources: [
      smSource,
      { label: 'sm-crypto · SM2 格式约定', url: 'https://github.com/JuneAndGreen/sm-crypto#sm2' },
    ],
  },
  md5: {
    summary: 'MD5 是产生 128 位结果的消息摘要算法，不属于可逆加密。',
    facts: [
      { label: '摘要长度', value: '128 位（16 字节）' },
      { label: 'Hex 长度', value: '32 个字符' },
      { label: '密钥', value: '不需要' },
    ],
    principle:
      'MD5 把任意长度的输入字节映射为固定长度摘要。不同输入可能得到相同摘要，MD5 的实用碰撞攻击已使它失去抗碰撞用途。',
    uses: '用于兼容历史校验值或调试旧接口。涉及恶意篡改或可信身份的场景应使用更合适的方案。',
    notes: [
      '不能用 MD5 证明文件未被恶意替换，也不应直接用它存储密码。',
      ...digestNotes.slice(0, 1),
      digestNotes[2],
    ],
    sources: [
      { label: 'RFC 6151 · MD5 安全性说明', url: 'https://www.rfc-editor.org/rfc/rfc6151.html' },
    ],
  },
  sha1: {
    summary: 'SHA-1 是输出 160 位摘要的单向哈希算法，本站保留它用于旧系统兼容。',
    facts: [
      { label: '摘要长度', value: '160 位（20 字节）' },
      { label: 'Hex 长度', value: '40 个字符' },
      { label: '密钥', value: '不需要' },
    ],
    principle:
      '输入字节经分组处理后得到固定长度摘要。SHA-1 的抗碰撞安全性已被攻破，不应依赖它建立新的抗碰撞设计。',
    uses: '用于比对历史摘要值和调试仍要求 SHA-1 的接口。新的通用摘要场景可选择 SHA-256。',
    notes: digestNotes,
    sources: [
      shaSource,
      { label: 'NIST · SHA-1 迁移说明', url: 'https://csrc.nist.gov/projects/hash-functions' },
    ],
  },
  sha256: {
    summary: 'SHA-256 属于 SHA-2 家族，输出 256 位摘要，是常见的通用哈希选择。',
    facts: [
      { label: '摘要长度', value: '256 位（32 字节）' },
      { label: 'Hex 长度', value: '64 个字符' },
      { label: '密钥', value: '不需要' },
    ],
    principle:
      'SHA-256 将可变长度的消息压缩为固定长度摘要。只要输入字节一致，结果就一致；改动输入通常会改变整个摘要。',
    uses: '用于数据指纹、文件摘要与协议调试。需要确认消息来源时，可以使用带共享密钥的 HMAC-SHA256。',
    notes: digestNotes,
    sources: [shaSource],
  },
  sha384: {
    summary: 'SHA-384 属于 SHA-2 家族，输出比 SHA-256 更长的 384 位摘要。',
    facts: [
      { label: '摘要长度', value: '384 位（48 字节）' },
      { label: 'Hex 长度', value: '96 个字符' },
      { label: '密钥', value: '不需要' },
    ],
    principle:
      'SHA-384 使用 SHA-512 家族的处理结构，但采用不同的初始值并截取结果；它不是直接截取普通 SHA-512 的输出。',
    uses: '用于明确要求 SHA-384 的协议、数据校验和认证值计算。选择摘要算法时应遵循对端协议约定。',
    notes: digestNotes,
    sources: [
      { label: 'RFC 6234 · SHA-384 / SHA-512', url: 'https://www.rfc-editor.org/rfc/rfc6234.html' },
    ],
  },
  sha512: {
    summary: 'SHA-512 属于 SHA-2 家族，输出 512 位摘要，常见于要求较长摘要的协议。',
    facts: [
      { label: '摘要长度', value: '512 位（64 字节）' },
      { label: 'Hex 长度', value: '128 个字符' },
      { label: '密钥', value: '不需要' },
    ],
    principle:
      'SHA-512 基于 64 位字运算处理消息分组，得到固定长度摘要。更长的摘要并不意味着所有使用场景都需要选择它。',
    uses: '用于指定 SHA-512 的校验和协议，也可作为 HMAC 的底层哈希；与对端一致比单纯增加输出长度更重要。',
    notes: digestNotes,
    sources: [
      { label: 'RFC 6234 · SHA-384 / SHA-512', url: 'https://www.rfc-editor.org/rfc/rfc6234.html' },
    ],
  },
  sm3: {
    summary: 'SM3 是国密消息摘要算法，输出固定的 256 位摘要，不提供解密操作。',
    facts: [
      { label: '摘要长度', value: '256 位（32 字节）' },
      { label: 'Hex 长度', value: '64 个字符' },
      { label: '密钥', value: '不需要' },
    ],
    principle:
      'SM3 将输入字节经过多轮压缩处理为摘要。它与 SHA-256 的输出长度相同，但计算过程不同，结果不能相互替代。',
    uses: '用于国密协议的数据摘要与校验；SM2 等协议也会使用 SM3 作为组成部分。',
    notes: digestNotes,
    sources: [smSource],
  },
  hmac: {
    summary: 'HMAC 把共享密钥与哈希算法结合，生成消息认证值，用于检查消息完整性与来源。',
    facts: [
      { label: '本站哈希', value: 'SHA-1 / 256 / 384 / 512' },
      { label: '密钥', value: '双方共享的原始字节' },
      { label: '输出长度', value: '与所选哈希的摘要长度一致' },
    ],
    principle:
      'HMAC 使用规范的内外两层哈希结构处理密钥和消息，并非简单地把密钥拼接到消息前后再计算摘要。',
    uses: '适合协议认证和请求完整性校验。持有同一密钥的一方可重新计算并比较认证值。',
    notes: [
      'HMAC 不会隐藏消息内容，也没有解密操作；需要保密时仍需加密。',
      '共享密钥的持有者都能生成认证值，因此 HMAC 不等同于公钥数字签名。',
      'HMAC 本身不防重放；协议还需要约定时间戳、随机数或序号。',
    ],
    sources: [{ label: 'RFC 2104 · HMAC', url: 'https://www.rfc-editor.org/rfc/rfc2104.html' }],
  },
  encoding: {
    summary: 'UTF-8、Hex 与 Base64 是数据表示方式。编码转换可以逆转，不会提供加密保护。',
    facts: [
      { label: 'UTF-8', value: '把文字编码为字节' },
      { label: 'Hex', value: '每个字节对应 2 个字符' },
      { label: 'Base64', value: '每 3 字节对应 4 个字符（含填充）' },
    ],
    principle:
      '先按输入编码还原字节，再以输出编码表示同一组字节。UTF-8 面向文本，Hex 与 Base64 可以表示任意二进制数据。',
    uses: '用于传输密钥、IV、密文和摘要，以及检查程序之间的文本与字节约定。',
    notes: [
      '本工具接受标准 Base64 的 + / 字母表和 = 填充，不接受 Base64URL。',
      '不是所有字节都能解码为有效 UTF-8；此时应选择 Hex 或 Base64 输出。',
      '中文、emoji 与换行会影响 UTF-8 字节长度；字数不等于字节数。',
    ],
    sources: [
      { label: 'RFC 4648 · Hex / Base64', url: 'https://www.rfc-editor.org/rfc/rfc4648.html' },
      { label: 'RFC 3629 · UTF-8', url: 'https://www.rfc-editor.org/rfc/rfc3629.html' },
    ],
  },
};
