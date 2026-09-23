# ZAYNOR — pendientes fuera de la prioridad actual

Este archivo separa el trabajo diferido de los dos issues que sí se van a
resolver ahora. No aplicar estos puntos en esta ronda.

Revisión solicitada antes de cerrar findings: `@dahgoth`.

## Diferido

- [ ] Revisar nuevamente los 21 flows de path injection después de una nueva
  corrida CodeQL, por primitive, caller y boundary.
- [ ] Confirmar si `sha256_file()` necesita una API de path permitido o si
  alcanza con mantener la validación en todos sus callers.
- [ ] Reejecutar CodeQL contra el HEAD actual y retirar alertas stale/false
  positive del dashboard cuando corresponda.
- [ ] Revisar Secret Scanning si se habilita en GitHub.
- [ ] Añadir una prueba de carrera para el reemplazo seguro del archivo
  temporal de tooling.
- [ ] Verificar endpoints HTTP desplegados si existe un backend público; la
  URL Vercel inspeccionada expone el frontend, no el API ZAYNOR.

## Regla de alcance

Los findings equivalentes que aparezcan más adelante en ANNACONDA se
documentan únicamente en un informe local de esa auditoría: no commit, no
push y no cambios de código.
