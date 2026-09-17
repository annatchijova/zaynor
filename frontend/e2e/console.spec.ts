import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("keeps the primary mock journey within the authority boundary", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Consola de análisis forense." })).toBeVisible();

  await page.getByRole("link", { name: "Abrir caso" }).click();
  await expect(page.getByRole("heading", { name: "CASE-001" })).toBeVisible();
  await expect(page.getByText("ABSTAIN", { exact: true }).first()).toBeVisible();

  const caseNavigation = page.getByRole("navigation", { name: "Caso" });

  await caseNavigation.getByRole("link", { name: "Evidencia", exact: true }).click();
  await expect(page.locator("caption")).toHaveText("Evidencia preservada en el snapshot del caso.");

  await caseNavigation.getByRole("link", { name: "Asistencia" }).click();
  await expect(page.getByText("La explicación se limita al paquete autoritativo ya sellado.")).toBeVisible();

  await caseNavigation.getByRole("link", { name: "Investigación" }).click();
  await expect(page.getByText("AUTHORITATIVE_RESULT_UNCHANGED")).toBeVisible();

  await page.getByLabel("Pregunta para el investigador local").fill("¿Qué evidencia adicional debería revisarse?");
  await page.getByRole("button", { name: "Solicitar investigación" }).click();
  await expect(page.getByRole("heading", { name: "P002" })).toBeVisible();
  await expect(page.getByText("La secuencia de investigación se actualizó desde el servicio local.")).toBeVisible();
  await expect(page.getByText("AUTHORITATIVE_RESULT_UNCHANGED")).toBeVisible();
});

test("returns authority-bounded answers for every suggested assistance question", async ({ page }) => {
  const suggestedQuestions = [
    "¿Qué encontró el motor y con qué evidencia lo sostiene?",
    "¿Por qué el sistema llegó a este veredicto?",
    "¿Qué preguntas todavía quedan sin responder?",
    "¿Qué debería revisar primero como analista?",
    "¿Este resultado podría cambiar con más evidencia?",
  ];

  for (const question of suggestedQuestions) {
    await page.goto("/cases/CASE-001/chat");
    await page.getByRole("button", { name: question }).click();
    await expect(page.getByLabel("Respuesta narrativa verificada")).toBeVisible();
    await expect(page.getByText("Esta explicación no modifica el veredicto autoritativo.")).toBeVisible();
  }
});

test("keeps authoritative findings distinct from investigation records", async ({ page }) => {
  await page.goto("/cases/CASE-001/senior");
  await expect(page.getByRole("heading", { name: "Matriz técnica de resultados" })).toBeVisible();
  await expect(page.getByText("Hallazgos autoritativos y las referencias que los sostienen o limitan.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Investigación no autoritativa" })).toBeVisible();

  await page.goto("/cases/CASE-001/investigation");
  await expect(page.getByText("No es un hallazgo")).toBeVisible();
  await expect(page.getByText("No es un veredicto")).toBeVisible();
  await expect(page.getByRole("heading", { name: "P001" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "O001" })).toBeVisible();
  await expect(page.getByText("AUTHORITATIVE_RESULT_UNCHANGED")).toBeVisible();
});

test("has no automatically detectable accessibility violations on core screens", async ({ page }) => {
  for (const path of ["/", "/cases/CASE-001", "/cases/CASE-001/evidence", "/cases/CASE-001/chat", "/cases/CASE-001/senior", "/cases/CASE-001/investigation"]) {
    await page.goto(path);
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
  }
});

test("keeps the primary mobile workflow within the viewport", async ({ page }) => {
  test.skip(test.info().project.name !== "mobile-chromium", "The mobile project provides the 375 px baseline.");

  await page.setViewportSize({ width: 375, height: 812 });

  for (const path of ["/", "/cases/CASE-001", "/cases/CASE-001/evidence", "/cases/CASE-001/chat", "/cases/CASE-001/senior", "/cases/CASE-001/investigation"]) {
    await page.goto(path);
    const hasHorizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
    expect(hasHorizontalOverflow).toBe(false);
  }
});
