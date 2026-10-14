import { Routes } from '@angular/router';
import { ALGORITHMS } from './crypto/registry';
export const routes: Routes = [
  ...ALGORITHMS.map((a) => ({
    path: `tool/${a.id}`,
    loadComponent: () => import('./workbench/workbench').then((m) => m.Workbench),
  })),
  { path: '', redirectTo: 'tool/aes', pathMatch: 'full' },
  { path: '**', redirectTo: 'tool/aes' },
];
