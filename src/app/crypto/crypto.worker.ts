/// <reference lib="webworker" />
import { runCrypto } from './engine';
import { WorkerTask } from './types';
addEventListener('message', async ({ data }: MessageEvent<WorkerTask & { id: number }>) => {
  try {
    const result =
      data.action === 'run'
        ? await runCrypto(data.request)
        : data.action === 'generate-rsa'
          ? await (await import('./rsa')).generateRsa(data.bits, data.format)
          : await (await import('./sm2')).generateSm2();
    postMessage({ id: data.id, result });
  } catch (error) {
    postMessage({
      id: data.id,
      error: error instanceof Error ? error.message : '计算失败，请检查参数。',
    });
  }
});
