import { DOCUMENT } from '@angular/common';
import { Injectable, effect, inject, signal } from '@angular/core';
import { translateEnglish } from './english';
export type Language = 'zh-CN' | 'en';
@Injectable({ providedIn: 'root' })
export class I18nService {
  private readonly document = inject(DOCUMENT);
  private readonly selectedLanguage = signal<Language>('zh-CN');
  readonly language = this.selectedLanguage.asReadonly();
  constructor() {
    effect(() => {
      this.document.documentElement.lang = this.language();
      this.document.title = this.t('Cipher Lab · 加解密工具箱');
      this.document
        .querySelector('meta[name="description"]')
        ?.setAttribute(
          'content',
          this.language() === 'en'
            ? 'A browser-local cryptography toolkit. AES, RSA, DES, SM2/SM3/SM4, digests, HMAC and encoding.'
            : '浏览器本地运行的加解密工作台。AES、RSA、DES、国密 SM2/SM3/SM4、摘要、HMAC 与编码转换。',
        );
    });
  }
  setLanguage(language: Language): void {
    this.selectedLanguage.set(language);
  }
  t(text: string): string {
    return this.language() === 'en' ? translateEnglish(text) : text;
  }
}
