# Pendientes para el frontend (Ivan)

Instrucciones concretas, con archivo/línea exacto. No hace falta tocar el
backend para ninguno de estos — todo lo que necesitan ya está expuesto.

## 1. Descarga de reportes rota en modo `http` (bug real, no cosmético)

`HttpApiClient.getReport()` (`src/lib/api/http-api-client.ts`) devuelve
`download_url` como ruta **relativa**: `/cases/{id}/reports/{fmt}/download`.
`ReportAction` (`src/components/reports/report-links.tsx:32`) la usa tal
cual en el `href`. Si el frontend y `zaynor serve` corren en orígenes
distintos (el caso normal: frontend en `:3000`, backend en `:8420`), el
link intenta descargar del dominio del FRONTEND, no del backend. 404.

**Arreglo:** en `HttpApiClient`, resolver `download_url` contra el propio
`#baseUrl` del cliente antes de devolverlo (`new URL(download_url,
this.#baseUrl).toString()`), o exponer `baseUrl` públicamente y resolverlo
en `report-links.tsx`. Cualquiera de las dos sirve — la primera es más
prolija porque `MockApiClient` sigue devolviendo `mock://...` sin tocar
nada.

**Cómo probarlo en serio:**
```bash
# Terminal 1 — backend real, con los 21+ casos ya congelados en /tmp
# (pedime el path exacto si lo necesitás, o corré tu propio freeze/analyze)
zaynor serve --output-root <output_root> --cases-root <cases_root> --port 8420 --model hermes3:8b

# Terminal 2 — frontend en modo http
cd frontend
NEXT_PUBLIC_ZAYNOR_API_MODE=http NEXT_PUBLIC_ZAYNOR_API_BASE_URL=http://127.0.0.1:8420 npm run dev
```
Abrí `/cases/<un-case-id>/reports` y confirmá que "Ver Markdown" /
"Exportar HTML" / "Exportar PDF" bajan contenido real, no un 404.

## 2. Rename "Junior" → "Asistencia" (feedback del mentor del hackathon)

Le encantó, pero sugirió que el chat no se llame "Junior" — tanto senior
como junior lo van a usar, depende de la pregunta, no del rol. Cambiar:

- `primary-navigation.tsx` — el ítem de nav "Junior" → "Asistencia"
- `case-navigation.tsx` — el tab correspondiente
- `junior-chat.tsx` / `junior-chat.module.css` — copy visible ("Consola
  junior" → "Consola de asistencia", etc.). No hace falta renombrar los
  archivos si no querés, pero sí el texto que ve el usuario.
- La ruta `/cases/{id}/chat` puede quedar igual — es interna, nadie la ve.

## 3. Modo http contra la investigación (nuevo, recién wireado)

`POST /cases/{id}/investigations/proposals` ya es real: el LLM propone,
pasa por policy gate determinista, y si se aprueba llama de verdad al
bridge MCP de VIGIA (no un mock). `InvestigationQueue`/
`investigation-timeline.tsx` ya tienen los tipos correctos
(`InvestigationProposal`/`Observation`) — probalo en modo http igual que
el punto 1 y confirmá que la cola muestra la propuesta + observación real
después de usar el composer de investigación (si el componente ya llama
a `api.proposeInvestigation`; si no lo llama todavía, hay que cablearlo
ahí — revisá `investigation-queue.tsx` para ver si ese POST está wireado
a algún botón o si falta el formulario).

## No es tuyo (aviso, no pedido)

Dos cosas que encontramos y quedan del lado del backend, no tocan nada
del frontend:
- El bundle (`bundle.json`) que genera cada análisis ya trae su propio
  audit trail (real, con hash por paso) y un devil's-advocate
  determinista (Eco's Razor) — ninguno de los dos está expuesto por
  ninguna ruta todavía. Si en algún momento querés mostrarlos, avisá
  antes de asumir que existe una ruta — hoy no existe.
