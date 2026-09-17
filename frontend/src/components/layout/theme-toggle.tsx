"use client";

import { useSyncExternalStore } from "react";

type Theme = "dark" | "light";

const storageKey = "zaynor-theme";
const themeChangeEvent = "zaynor-theme-change";

function getTheme(): Theme {
  const savedTheme = localStorage.getItem(storageKey);

  if (savedTheme === "dark" || savedTheme === "light") {
    return savedTheme;
  }

  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function subscribe(onStoreChange: () => void) {
  const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const handleSystemThemeChange = () => {
    if (!localStorage.getItem(storageKey)) {
      onStoreChange();
    }
  };

  mediaQuery.addEventListener("change", handleSystemThemeChange);
  window.addEventListener(themeChangeEvent, onStoreChange);

  return () => {
    mediaQuery.removeEventListener("change", handleSystemThemeChange);
    window.removeEventListener(themeChangeEvent, onStoreChange);
  };
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document
    .querySelector('meta[name="color-scheme"]')
    ?.setAttribute("content", theme);
  localStorage.setItem(storageKey, theme);
  window.dispatchEvent(new Event(themeChangeEvent));
}

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, getTheme, () => "light");

  const nextTheme = theme === "dark" ? "light" : "dark";

  const themeLabels: Record<Theme, string> = { dark: "Tema oscuro", light: "Tema claro" };

  return (
    <button
      aria-label={`Cambiar a ${themeLabels[nextTheme].toLocaleLowerCase("es-AR")}`}
      aria-pressed={theme === "dark"}
      className="theme-toggle"
      onClick={() => {
        applyTheme(nextTheme);
      }}
      type="button"
    >
      <span aria-hidden="true" className="theme-toggle__mark" />
      {themeLabels[nextTheme]}
    </button>
  );
}
