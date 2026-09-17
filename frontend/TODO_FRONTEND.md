# Pendientes del frontend

## Resueltos (Claude, ante la ausencia de Ivan)

Los tres pendientes que estaban acá (descarga de reportes rota en modo
`http`, rename "Junior" → "Asistencia", wiring de la cola de investigación
al endpoint real) se resolvieron directamente:

1. **Descarga de reportes**: `HttpApiClient.getReport()` ahora resuelve
   `download_url` contra su propio `#baseUrl` antes de devolverlo.
   Verificado contra un backend real (`zaynor serve`), no solo en mock.
2. **Rename**: "Junior" → "Asistencia" en `primary-navigation.tsx`,
   `case-navigation.tsx`, el eyebrow de `junior-chat.tsx`, y el copy del
   `/about` que enmarcaba el chat como "para juniors".
3. **Cola de investigación**: `investigation-queue.tsx` ahora tiene el
   formulario real, llamando a `api.proposeInvestigation(caseId,
   {question})`. De paso se corrigió `InvestigationRequest` — tenía
   `requested_tool`/`arguments` que el backend real (`InvestigationProposalRequest`
   en `api.py`, solo declara `question`) ignoraba en silencio; el modelo
   elige la herramienta, no el usuario.

## No es tuyo (aviso, no pedido)

Dos cosas que encontramos y quedan del lado del backend, no tocan nada
del frontend:
- El bundle (`bundle.json`) que genera cada análisis ya trae su propio
  audit trail (real, con hash por paso) y un devil's-advocate
  determinista (Eco's Razor) — ninguno de los dos está expuesto por
  ninguna ruta todavía. Si en algún momento querés mostrarlos, avisá
  antes de asumir que existe una ruta — hoy no existe.
