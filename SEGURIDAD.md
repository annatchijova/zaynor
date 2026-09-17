# Política de Seguridad de ZAYNOR

*[Read this in English](SECURITY.md)*

## Reportar una vulnerabilidad

**No abras un issue público para una vulnerabilidad.** Escribí por mail a
`anna.tchijova@icloud.com`. No incluyas detalles del exploit, evidencia
 sensible, credenciales ni datos privados de casos en issues o pull requests
 públicas.

Incluí una descripción breve, el componente o versión afectada, pasos de
reproducción o una prueba de concepto mínima, y el impacto de seguridad o
forense esperado. El mantenimiento acusará recibo cuando sea posible y
coordinará una corrección o mitigación. No publiques el reporte hasta recibir
confirmación de que es seguro hacerlo.

| Severidad | Qué significa | Tiempo de respuesta |
|---|---|---|
| Crítica | Se puede falsificar o alterar un resultado sellado sin detectarlo, o influir un veredicto | 48 horas |
| Alta | Se puede eludir una protección de paths, symlinks, allowlist o alcanzar un backend no local | 7 días |
| Media/Baja | Cualquier otro problema | mejor esfuerzo |

## Arquitectura de seguridad

Estos son límites implementados, no promesas sobre cualquier despliegue:

### Autoridad e integridad del veredicto

- `result.json` y `result.seal.json` son autoritativos sólo después de la
  verificación criptográfica mediante `verify_authoritative_result()`.
- El loader compartido vincula el `case_id` pedido, carga ambos artefactos,
  verifica el sello y falla cerrado ante datos inválidos o incompatibles.
- `answer_question()` y la API verifican autoridad antes de invocar al
  narrador. Chat nunca ejecuta el análisis de VIGÍA ni recalcula el veredicto.
- El LLM narra un resultado verificado; no puede crear, modificar ni
  reemplazar resultados, sellos, findings o veredictos.
- Los guards comparan los claims con hechos sellados y eliminan o rechazan
  claims no soportados antes de mostrar la narración.

### Evidencia y filesystem

- Los case IDs y paths se validan en el borde.
- Las capas de CLI y acceso a evidencia rechazan traversal y symlink traversal.
- El acceso a evidencia es de sólo lectura salvo operaciones explícitamente
  documentadas.
- Artefactos ausentes, malformados, manipulados o de otro caso fallan cerrado.

### Frontera del modelo local

- El cliente Ollama acepta únicamente hosts loopback: `127.0.0.1`,
  `localhost` o `::1`.
- Host, modelo y timeout son configurables; las requests usan `/api/generate`
  local y desactivan streaming explícitamente.
- El runtime soportado no tiene fallback cloud ni proveedores externos.
- La API rechaza modelos no soportados y no presenta usage desconocido como
  una medición real de cero.

### API y transporte

- Requests malformadas, case IDs inválidos, casos ausentes, autoridad inválida,
  Ollama no disponible y fallos internos usan errores HTTP estructurados.
- El streaming se rechaza explícitamente cuando no está implementado.
- Los IDs de completion usan UUIDs, no segundos del reloj.
- CORS queda restringido a orígenes localhost de OpenWebUI; no se habilita `*`.
- Los errores públicos no exponen paths internos ni detalles de excepciones.

### Hashes, sellos y registros

Los sellos de autoridad son digests SHA-256 deterministas sobre la
representación canónica tipada del resultado. Metadata y cadenas de auditoría
no reemplazan el sello del resultado. Cuando haya hash chain o audit chain,
verificá la cadena y sus anclas antes de tratar el registro como íntegro.
Varios hashes representan verificaciones distintas; no permiten omitir ninguna.

## Checklist de despliegue

- [ ] Roots de evidencia y resultados dedicados y con acceso restringido.
- [ ] `result.json` y `result.seal.json` conservados juntos.
- [ ] Autoridad verificada antes de compartir resultado o narración.
- [ ] Ollama ligado a loopback y con un modelo local aprobado.
- [ ] Exposición de API y CORS configurados intencionalmente.
- [ ] Hash/audit chain verificada cuando forme parte del despliegue.
- [ ] Logs y reportes sin credenciales ni evidencia sensible innecesaria.
- [ ] Backups de resultados, sellos y auditoría probados por integridad.

## Problemas en VIGÍA

`vendor/vigia_engine/` es una frontera de dependencia upstream. Reportá a sus
mantenedores los problemas que pertenezcan a VIGÍA y avisá a ZAYNOR cuando
afecten la integración. No parches silenciosamente comportamiento upstream en
una corrección de seguridad de ZAYNOR sin documentar el impacto contractual.
