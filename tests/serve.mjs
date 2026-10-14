import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
const root = path.resolve('dist/online-encryption/browser');
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
};
http
  .createServer(async (req, res) => {
    try {
      const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      if (!pathname.startsWith('/online-encryption/')) {
        res.writeHead(404).end();
        return;
      }
      const file = path.resolve(root, pathname.slice('/online-encryption/'.length) || 'index.html');
      if (!file.startsWith(root + path.sep) || !(await stat(file)).isFile()) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, {
        'Content-Type': mime[path.extname(file)] ?? 'application/octet-stream',
        'Cache-Control': 'no-store',
      });
      res.end(await readFile(file));
    } catch {
      res.writeHead(404).end();
    }
  })
  .listen(4173, '127.0.0.1', () =>
    console.log('Preview: http://127.0.0.1:4173/online-encryption/'),
  );
