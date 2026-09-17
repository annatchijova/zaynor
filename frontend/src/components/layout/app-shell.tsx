import Link from "next/link";
import { Suspense, type ReactNode } from "react";

import { PrimaryNavigation, PrimaryNavigationFallback } from "./primary-navigation";
import { ThemeToggle } from "./theme-toggle";

interface AppShellProps {
  readonly children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Saltar al contenido
      </a>
      <header className="app-header">
        <div className="app-header__inner">
          <Link aria-label="Inicio de ZAYNOR" className="brand" href="/">
            <span aria-hidden="true" className="brand__mark" />
            <span>ZAYNOR</span>
          </Link>
          <div className="app-header__controls">
            <span className="environment-label">Consola forense local</span>
            <ThemeToggle />
          </div>
        </div>
        <Suspense fallback={<PrimaryNavigationFallback />}>
          <PrimaryNavigation />
        </Suspense>
      </header>
      <main id="main-content" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
