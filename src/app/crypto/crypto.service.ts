import { Injectable, OnDestroy } from '@angular/core';
import { CryptoResult, KeyPair, WorkerTask } from './types';
@Injectable({ providedIn: 'root' })
export class CryptoService implements OnDestroy {
  private worker?: Worker;
  private counter = 0;
  private pending = new Map<
    number,
    { resolve: (value: CryptoResult | KeyPair) => void; reject: (error: Error) => void }
  >();
  execute(task: WorkerTask): Promise<CryptoResult | KeyPair> {
    if (!this.worker) {
      if (
        !globalThis.isSecureContext ||
        typeof Worker === 'undefined' ||
        !globalThis.crypto?.subtle
      )
        return Promise.reject(
          new Error(
            '需要支持 Web Crypto 与 Web Worker 的现代浏览器，请通过 HTTPS 或 localhost 访问。',
          ),
        );
      this.worker = new Worker(new URL('./crypto.worker', import.meta.url), { type: 'module' });
      this.worker.onmessage = ({ data }) => {
        const pending = this.pending.get(data.id);
        this.pending.delete(data.id);
        if (data.error) pending?.reject(new Error(data.error));
        else pending?.resolve(data.result);
      };
      this.worker.onerror = () => {
        this.reset('计算线程无法启动，请刷新页面后重试。');
      };
      this.worker.onmessageerror = () => this.reset('计算线程通信失败，请重试。');
    }
    const id = ++this.counter;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker!.postMessage({ ...task, id });
    });
  }
  reset(message = '计算已取消。'): void {
    this.worker?.terminate();
    this.worker = undefined;
    for (const pending of this.pending.values()) pending.reject(new Error(message));
    this.pending.clear();
  }
  ngOnDestroy(): void {
    this.reset();
  }
}
