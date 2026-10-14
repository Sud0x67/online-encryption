# Cipher Lab · 加解密工具箱

纯静态 Angular 22 开发调试工具。全部计算在浏览器 Web Worker 中完成，不需要后端。

- 网站：[sud0x67.github.io/online-encryption](https://sud0x67.github.io/online-encryption/)
- 源码：[Sud0x67/online-encryption](https://github.com/Sud0x67/online-encryption)

## 本地运行

需要 Node.js **24.15.0 以上的 24.x**；项目固定使用 24.21.0。支持读取 `.nvmrc` / `.node-version` 的版本管理器。

```sh
nvm use                 # 如果使用 nvm
npm ci
npm start              # http://localhost:4200
```

本次工作环境另外准备了独立 Node 24，可在终端执行：

```sh
export PATH=$HOME/software/node-24.21.0/bin:$PATH
npm start
```

```sh
npm run check          # 测试及算法代码的 TypeScript 检查
npm test               # Vitest，标准向量及 OpenSSL 互通测试
npm run build          # 生产静态构建，基础路径 /online-encryption/
npm run preview        # http://127.0.0.1:4173/online-encryption/
npx playwright install chromium firefox webkit
npm run test:e2e       # Chromium、Firefox、WebKit、移动端
```

右上角「中文 / EN」可切换界面、算法介绍与校验提示。默认简体中文；语言选择在当前页面与算法导航之间保持，刷新后恢复中文。切换语言保留输入、参数、密钥、结果及当前子 Tab，不会重新计算；语言偏好也不会写入本地存储。

每个工具页包含「工具」与「算法介绍」两个子 Tab，默认显示工具。介绍页提供基本原理、参数概览、常见用途、使用要点和标准参考资料；切换 Tab 保留输入、密钥与计算结果。

## 算法与约定

| 工具       | 支持参数                                                  |
| ---------- | --------------------------------------------------------- |
| AES        | 16/24/32 字节原始密钥；GCM/CBC/CTR/ECB                    |
| DES / 3DES | 8 / 24 字节原始密钥；CBC/ECB                              |
| SM4        | 16 字节原始密钥；CBC/ECB                                  |
| RSA        | OAEP（SHA-1/SHA-256，MGF1 同摘要，空 label）、PKCS#1 v1.5 |
| SM2        | C1C3C2 / C1C2C3；可选择密文是否含 04 前缀                 |
| 摘要       | MD5、SHA-1/256/384/512、SM3                               |
| HMAC       | SHA-1/256/384/512                                         |
| 编码       | UTF-8 / Hex / 标准 Base64                                 |

- 所有长度都按**字节**计算。UTF-8 中汉字、emoji 不等于单个字节。
- Hex 必须为偶数位，无 `0x` 前缀；Hex、Base64 可包含空白字符。Base64 必须使用标准 `+/` 字母表、正确的 `=` 填充及规范尾部位，不接受 Base64URL。
- CBC/ECB 支持 PKCS#7 或无填充。无填充要求输入为块长度的整数倍；解密验证 PKCS#7 的每一个填充字节。
- CBC IV 与块长度一致（AES/SM4 16，DES/3DES 8 字节）；CTR 使用 16 字节初始计数器，计数器长度固定 128 位；ECB 不使用 IV。
- AES-GCM 使用 12 字节 IV、16 字节标签，可输入 AAD。**密文与标签单独输出**。其他程序如输出 `ciphertext || tag`，请拆分最后 16 字节作为标签。同一密钥下实际加密必须使用唯一 IV。
- 密钥按输入字节使用，不截断、不补齐、不执行口令派生；不支持 OpenSSL `Salted__` / CryptoJS 口令封装。
- RSA 公钥支持 SPKI 和 PKCS#1 PEM；私钥支持未加密 PKCS#8 和 PKCS#1 PEM。不支持加密 PEM、证书、JWK 或自动分段。OAEP 最大明文长度为 `模数字节数 - 2 × 摘要字节数 - 2`；v1.5 为 `模数字节数 - 11`。生成位数支持 2048/3072/4096。
- SM2 公钥支持 `04 + X + Y` 未压缩 Hex 点和 `02/03 + X` 压缩点；私钥为 32 字节 Hex。密文的 C1 为未压缩 X/Y，默认含 `04` 前缀，不接受 ASN.1 DER 密文。加解密双方必须明确使用相同顺序和前缀选项。
- UTF-8 输出严格校验；不能解码的字节请改用 Hex/Base64 重新计算。
- 输入或参数变化后旧结果标为失效，复制和回填按钮禁用；只有执行完成的当前结果可回填。切换算法、清空或刷新页面清除当前数据。

## 互通示例

AES-128-CBC / PKCS#7，UTF-8 明文 `hello`，密钥与 IV 均为 16 个零字节。本站使用 Hex 输入密钥、IV，Base64 输出：

```sh
printf '%s' 'hello' | openssl enc -aes-128-cbc \
  -K 00000000000000000000000000000000 \
  -iv 00000000000000000000000000000000 -a -A
```

这是一组固定**测试参数**；实际加密请生成自己的密钥与 IV。

RSA-OAEP 的 OpenSSL 参数需要明确指定两个摘要：

```sh
openssl pkeyutl -encrypt -pubin -inkey public.pem \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
  -in plaintext.bin -out ciphertext.bin
openssl base64 -A -in ciphertext.bin
```

`tests/fixtures/openssl.json` 是 OpenSSL 3.5.7 `enc` / `pkeyutl` 生成的固定互通数据，含专用的可公开测试密钥，与任何真实数据无关。SM2 原始密文由 OpenSSL DER 的 X/Y、C3、C2 分量转换而来。算法测试另覆盖 FIPS 197、NIST SP 800-38A/GCM、RFC 4231 和国密标准向量。

## 结构与隐私

算法注册表声明工具分类和模式；编码层统一解析字节；算法适配器负责原生 Web Crypto 或按需加载的 node-forge / sm-crypto；独立 Worker 处理计算和密钥生成。Angular Material、Signals 与 Reactive Forms 管理界面。

本站仅请求静态资源。明文、密钥、IV 与结果不会发送到服务器，也不会写入 URL、控制台、cookies、localStorage、sessionStorage、IndexedDB 或 Service Worker 缓存。复制到系统剪贴板只在用户点击复制时执行。没有外部字体、CDN 脚本或分析埋点。

首次访问仍需从 GitHub Pages 下载静态资源。工具不包含文件加解密、签名验签、历史记录或账号。仅支持现代浏览器，通过 HTTPS 或 localhost 使用。

## 兼容算法与依赖限制

DES/3DES、ECB、MD5、SHA-1 提供给旧系统兼容与调试，界面包含用途提示。摘要是单向计算；编码转换不是加密。

`node-forge@1.4.0` 当前有未修复的 RSA PKCS#1 v1.5 **签名验签**漏洞 [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv)。本项目没有签名验签功能，不调用 `verify`，该公告涉及的接口不在执行路径中；`npm audit` 仍会报告该漏洞。不要在此依赖版本上增加签名验签功能。

`sm-crypto` 固定为 0.5.7。该库无法区分有效空消息与认证失败的空数组，因此适配器对空消息额外使用库的椭圆曲线运算验证 C3；相关内部接口有独立回归测试，升级时必须重新验证。

## GitHub Pages 部署

仓库 Pages 来源设置为 **GitHub Actions**。推送 `main` 后，`.github/workflows/pages.yml` 在 Node 24 下执行类型检查、算法测试、生产构建、四组浏览器测试；全部通过后通过官方 Pages Actions 部署。

PR 只执行验证，不部署。浏览器失败时上传截图、trace 和报告。部署内容为 `dist/online-encryption/browser`，hash 路由可以在 Pages 子路径直接刷新。发布状态以 GitHub Actions 的成功记录及实际网站访问为准。
