import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTabsModule } from '@angular/material/tabs';
import { ALGORITHM_GUIDES } from './algorithm-guides';
import { algorithmById, defaults } from '../crypto/registry';
import { CryptoService } from '../crypto/crypto.service';
import { decode, encode } from '../crypto/encoding';
import { CryptoResult, Encoding, Hash, KeyPair, Operation } from '../crypto/types';
@Component({
  selector: 'app-workbench',
  imports: [
    ReactiveFormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatCheckboxModule,
    MatProgressBarModule,
    MatTabsModule,
  ],
  templateUrl: './workbench.html',
  styleUrl: './workbench.scss',
})
export class Workbench {
  private readonly cryptoService = inject(CryptoService);
  private readonly snack = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);
  readonly algorithm = algorithmById(inject(ActivatedRoute).snapshot.url.at(-1)?.path ?? 'aes');
  readonly guide = ALGORITHM_GUIDES[this.algorithm.id];
  readonly form = inject(FormBuilder).nonNullable.group(defaults(this.algorithm.id));
  readonly p = signal(this.form.getRawValue());
  readonly busy = signal(false);
  readonly error = signal('');
  readonly result = signal<CryptoResult | null>(null);
  readonly stale = signal(false);
  readonly elapsed = signal(0);
  readonly encodings: { value: Encoding; label: string }[] = [
    { value: 'utf8', label: 'UTF-8 文本' },
    { value: 'hex', label: 'Hex' },
    { value: 'base64', label: 'Base64' },
  ];
  readonly hashes: Hash[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
  readonly isCipher =
    this.algorithm.category === 'symmetric' || this.algorithm.category === 'asymmetric';
  readonly isSymmetric = this.algorithm.category === 'symmetric';
  readonly needsKey = this.isSymmetric || this.algorithm.id === 'hmac';
  readonly isBlock = computed(() => this.isSymmetric && !['GCM', 'CTR'].includes(this.p().mode));
  readonly inputBytes = computed(() => {
    try {
      return decode(this.p().input, this.p().inputEncoding).length + ' bytes';
    } catch {
      return '编码待修正';
    }
  });
  readonly warning = computed(() =>
    this.algorithm.badge === '兼容'
      ? this.algorithm.category === 'digest'
        ? '仅用于兼容或校验；MD5、SHA-1 不适用于抗碰撞场景和密码存储。'
        : 'DES / 3DES 仅用于旧系统兼容，不建议用于新的安全设计。'
      : this.isSymmetric && this.p().mode === 'ECB'
        ? 'ECB 会暴露重复数据的模式，仅用于兼容与调试。'
        : this.algorithm.id === 'rsa' && this.p().rsaScheme === 'PKCS1'
          ? 'PKCS#1 v1.5 用于兼容；新的加密设计优先选择 OAEP。'
          : '',
  );
  private revision = 0;
  constructor() {
    this.form.valueChanges.pipe(takeUntilDestroyed()).subscribe(() => {
      this.p.set(this.form.getRawValue());
      this.revision++;
      if (this.result()) this.stale.set(true);
      this.error.set('');
    });
    this.destroyRef.onDestroy(() => this.cryptoService.reset());
  }
  operation(value: Operation): void {
    this.form.patchValue({
      operation: value,
      inputEncoding: value === 'decrypt' ? 'base64' : 'utf8',
      outputEncoding: value === 'decrypt' ? 'utf8' : 'base64',
    });
  }
  async run(): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set('');
    this.result.set(null);
    this.stale.set(false);
    const revision = this.revision,
      start = performance.now();
    try {
      const result = (await this.cryptoService.execute({
        action: 'run',
        request: { algorithm: this.algorithm.id, params: this.form.getRawValue() },
      })) as CryptoResult;
      if (this.destroyRef.destroyed) return;
      this.result.set(result);
      this.elapsed.set(Math.round(performance.now() - start));
      this.stale.set(revision !== this.revision);
    } catch (error) {
      if (!this.destroyRef.destroyed)
        this.error.set(error instanceof Error ? error.message : '计算失败。');
    } finally {
      if (!this.destroyRef.destroyed) this.busy.set(false);
    }
  }
  random(field: 'key' | 'iv'): void {
    const p = this.p();
    const length =
      field === 'key'
        ? this.algorithm.id === 'des'
          ? 8
          : this.algorithm.id === '3des'
            ? 24
            : this.algorithm.id === 'sm4'
              ? 16
              : p.keySize / 8
        : p.mode === 'GCM'
          ? 12
          : this.algorithm.id === 'des' || this.algorithm.id === '3des'
            ? 8
            : 16;
    this.form.patchValue({
      [field]: encode(crypto.getRandomValues(new Uint8Array(length)), 'hex'),
      [field + 'Encoding']: 'hex',
    });
  }
  async generateKeys(): Promise<void> {
    if (this.busy()) return;
    const revision = this.revision;
    this.busy.set(true);
    this.error.set('');
    try {
      const pair = (await this.cryptoService.execute(
        this.algorithm.id === 'rsa'
          ? { action: 'generate-rsa', bits: this.p().rsaBits, format: this.p().pemFormat }
          : { action: 'generate-sm2' },
      )) as KeyPair;
      if (!this.destroyRef.destroyed && revision === this.revision) this.form.patchValue(pair);
    } catch (error) {
      if (!this.destroyRef.destroyed)
        this.error.set(error instanceof Error ? error.message : '生成失败。');
    } finally {
      if (!this.destroyRef.destroyed) this.busy.set(false);
    }
  }
  example(): void {
    if (this.busy()) return;
    this.clear();
    this.form.patchValue({ input: 'Hello, Cipher Lab! 你好 🔐' });
    if (this.needsKey) this.random('key');
    if (this.isSymmetric && this.p().mode !== 'ECB') this.random('iv');
    if (this.algorithm.category === 'asymmetric') void this.generateKeys();
  }
  clear(): void {
    this.cryptoService.reset();
    this.form.reset(defaults(this.algorithm.id));
    this.result.set(null);
    this.stale.set(false);
    this.error.set('');
    this.elapsed.set(0);
  }
  refill(): void {
    const result = this.result();
    if (!result || this.stale()) return;
    const p = this.p();
    this.form.patchValue({
      input: result.output,
      inputEncoding: p.outputEncoding,
      outputEncoding: p.operation === 'encrypt' ? 'utf8' : 'base64',
      ...(this.isCipher ? { operation: p.operation === 'encrypt' ? 'decrypt' : 'encrypt' } : {}),
      ...(result.tag !== undefined ? { tag: result.tag } : {}),
    });
    this.result.set(null);
    this.stale.set(false);
  }
  async copy(value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      this.snack.open('已复制到剪贴板', '关闭', { duration: 2200 });
    } catch {
      this.snack.open('复制失败，请手动选择结果复制。', '关闭', { duration: 3500 });
    }
  }
}
