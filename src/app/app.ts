import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { I18nService } from './i18n/i18n.service';
import { ALGORITHMS } from './crypto/registry';
@Component({
  host: { '[class.english]': "i18n.language() === 'en'" },
  selector: 'app-root',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  readonly i18n = inject(I18nService);
  readonly t = (text: string) => this.i18n.t(text);
  readonly groups = [...new Set(ALGORITHMS.map((a) => a.group))].map((name) => ({
    name,
    algorithms: ALGORITHMS.filter((a) => a.group === name),
  }));
}
