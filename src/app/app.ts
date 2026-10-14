import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ALGORITHMS } from './crypto/registry';
@Component({
  selector: 'app-root',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  readonly groups = [...new Set(ALGORITHMS.map((a) => a.group))].map((name) => ({
    name,
    algorithms: ALGORITHMS.filter((a) => a.group === name),
  }));
}
