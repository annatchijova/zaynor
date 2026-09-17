import type { Metadata } from "next";
import Script from "next/script";
import type { ReactNode } from "react";

import { AppShell } from "@/components/layout/app-shell";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "ZAYNOR | Consola forense",
    template: "%s | ZAYNOR",
  },
  description: "Consola local para el análisis postmortem de casos DFIR.",
};

interface RootLayoutProps {
  readonly children: ReactNode;
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="es" suppressHydrationWarning>
      <head>
        <meta content="light dark" name="color-scheme" />
      </head>
      <body>
        <Script id="zaynor-theme" strategy="beforeInteractive">
          {`try { const theme = localStorage.getItem("zaynor-theme"); if (theme === "dark" || theme === "light") { document.documentElement.dataset.theme = theme; document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", theme); } } catch {}`}
        </Script>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
