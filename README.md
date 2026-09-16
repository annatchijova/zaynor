# Zaynor — investigación DFIR local y trazable

*[Read this in English](./README.en.md)*

> Estado: prototipo activo para Hackathon CyberAr 2026. Zaynor se está
> ensamblando mediante la migración de capacidades de tres repositorios
> existentes; la integración del producto continúa en este checkout.

## El problema real

Después de un incidente, un analista debe reconstruir qué ocurrió a partir de
logs de autenticación, procesos, red, filesystem, tickets y notas operativas.
Las fuentes pueden ser incompletas, contradictorias o contener texto
controlado por un atacante. La correlación manual es lenta. Un asistente
genérico basado en LLM puede ser rápido, pero también puede inventar hechos,
sobreafirmar causalidad o tratar una frase dentro de un log como una orden.

Zaynor responde una pregunta concreta:

> ¿Qué sostiene la evidencia, qué explicaciones alternativas fueron
> consideradas, qué conviene investigar después y qué todavía no puede saberse?

Zaynor no pretende ser un SIEM, un EDR ni un sistema de monitoreo en tiempo
real. Es una herramienta local de investigación DFIR post-incidente.

## Qué hace

Zaynor recibe un incidente ya declarado y evidencia ya recolectada. Congela el
caso, preserva la identidad de sus artefactos y pasa la evidencia al motor
matemático determinista. Ese motor produce y sella el resultado autoritativo
con una de estas etiquetas públicas:

```text
MALICE | ABSTAIN | UNKNOWN | BENIGN | SUSPICION
```

La IA no detecta ni decide el veredicto. Después del sellado, un LLM local
puede decidir qué investigar a continuación, proponer una operación de lectura
acotada y explicar el resultado para distintas audiencias. Si una consulta
produce nueva evidencia, esa evidencia vuelve a pasar por el motor
matemático antes de modificar cualquier resultado autoritativo.

El principio arquitectónico es:

> **La IA decide qué investigar. El motor matemático determinista decide qué
> sostiene la evidencia.**

El motor cuadripartito de la línea VIGÍA existe como capacidad técnica. Su
explicación detallada, score y semántica interna forman parte de la
profundización posterior; este README prioriza la frontera de autoridad que el
jurado puede observar en la demo.

## Flujo de autoridad

```text
INCIDENTE DECLARADO + EVIDENCIA RECOLECTADA
        (fixture simulado o datos públicos autorizados)
    -> freeze del caso: manifest, hashes, case_id inmutable
    -> motor matemático determinista
    -> veredicto autoritativo sellado
    -> contexto exhaustivo de MITRE ATT&CK / NIST
    -> IA local propone qué investigar después
    -> operación tipada, read-only y acotada
    -> nueva evidencia -> reanálisis determinista -> nuevo sellado
    -> chat local, vista técnica e informe para humanos
```

La IA nunca puede:

- escribir directamente el veredicto o el resultado sellado;
- crear referencias a evidencia que no devolvió una herramienta real;
- ejecutar shell, red arbitraria o escritura en el filesystem;
- convertir una ambigüedad en una conclusión segura;
- ejecutar una recomendación defensiva.

Una instrucción escrita dentro de un log, ticket o artefacto sigue siendo
**evidencia no confiable**, nunca una orden del sistema.

## Audiencias

### Perito junior

El perito junior dispone del chat completo con el LLM local que se está
migrando a Zaynor para preguntar por el caso en lenguaje natural. Es una
capacidad de primera clase del producto, no un extra futuro. El chat explica:

1. qué se observó;
2. por qué es relevante;
3. qué evidencia respalda cada explicación;
4. qué alternativas se consideraron;
5. qué conviene consultar después;
6. qué permanece desconocido.

El chat ayuda a investigar y comprender. No es un segundo motor de veredictos
ni puede ejecutar remediaciones.

### Analista senior

La vista técnica conserva artefactos congelados, provenance, timeline,
fracturas, hipótesis, referencias de evidencia, estado del veredicto, contexto
MITRE/NIST, auditoría y preguntas abiertas.

### Responsable del incidente

La vista ejecutiva resume el resultado sellado, la secuencia respaldada, la
incertidumbre material, el contexto de frameworks y las acciones defensivas
propuestas. Las acciones aparecen como `PROPOSED` y `NOT EXECUTED`.

## Caso de demostración

La demo utiliza `INC-2026-DEMO-001`, un incidente Linux simulado:

```text
login privilegiado desde un dispositivo desconocido
    -> sesión SSH en srv-files-01
    -> proceso que crea collection.zip
    -> cambio de metadata temporal
    -> conexión saliente relacionada
    -> nota operativa que intenta manipular al investigador
```

El sistema debe mostrar tanto lo que puede establecer como lo que no puede
establecer. La identidad de la persona frente al teclado, el origen de la
credencial y la transferencia completa del archivo permanecen desconocidos si
la evidencia congelada no los prueba.

El fixture o replay sintético sirve para poner en pantalla un caso ya
formado. No representa monitoreo real ni convierte a Zaynor en un SIEM.

## Demo de tres minutos

La explicación recomendada para el jurado es:

1. **Problema:** evidencia dispersa, contradictoria y potencialmente
   manipulable.
2. **Veredicto sellado:** el motor determinista produce una etiqueta pública
   antes de llamar al LLM.
3. **Investigación:** el LLM local elige una pregunta discriminante y solo
   puede usar herramientas read-only.
4. **Manipulación:** aparece una instrucción dentro de un artefacto; se registra
   como dato no confiable y no cambia permisos, herramientas ni veredicto.
5. **Explicación:** el perito junior pregunta al chat local por el resultado y
   por lo que falta investigar.
6. **Cierre:** se muestran hechos respaldados, incertidumbres, contexto
   MITRE/NIST y acciones propuestas.

> **La IA investiga. La evidencia y el motor determinista deciden.**

## Requisitos y soberanía

- Todo el procesamiento ocurre localmente.
- La inferencia utiliza Ollama u otro backend local equivalente.
- Ningún dato del caso se envía a un servicio externo.
- Solo se utilizan datos simulados o públicos autorizados.
- El modelo trabaja con operaciones explícitas, read-only y con límites de
  pasos, tiempo, bytes y resultados.
- No se realizan pruebas sobre sistemas reales.

## Estado y alcance

El repositorio está integrando capacidades existentes, no construyendo una
plataforma desde cero. El árbol actual contiene, entre otras piezas, el
congelamiento de casos, hashes y custodia, herramientas de evidencia
read-only, contrato de adaptación a VIGÍA, cliente MCP local, log de
investigación y el escenario sintético de demostración.

La integración final debe conservar estas propiedades:

- el mismo caso congelado y la misma configuración producen el mismo resultado
  autoritativo;
- activar o desactivar el LLM no cambia el resultado sellado;
- todo finding tiene referencias trazables;
- las referencias inventadas son rechazadas;
- path traversal, herramientas no autorizadas y escrituras son rechazados;
- el artefacto adversarial no puede modificar el estado de autoridad;
- la evidencia faltante o ambigua permanece como `UNKNOWN`;
- el contexto exhaustivo de MITRE y NIST no promueve un finding;
- el chat del perito junior solo explica hechos autorizados.

## Fuera del alcance actual

No forman parte de la demostración actual:

- monitoreo o recolección en tiempo real;
- adquisición desde sistemas reales;
- remediación autónoma;
- shell, red arbitraria o escritura para el LLM;
- renderizado PDF o HTML;
- un SIEM, EDR o producto de escala operacional.

El monitoreo en tiempo real, nuevos formatos de reporte y conectores
operacionales quedan como mejoras posteriores. El chat local completo y el
contexto exhaustivo de MITRE/NIST sí forman parte del producto que se está
integrando.

## Documentación

- [`docs/extra_arenaai.md`](./docs/extra_arenaai.md) — posición formal del
  producto, usuarios, demo, alcance y criterios de aceptación.
- [`AGENTS.md`](./AGENTS.md) — contratos de integración con VIGÍA y límites de
  autoridad entre evidencia, motor determinista y LLM.
- [`docs/proposal.en.md`](./docs/proposal.en.md) — propuesta de arquitectura.
- [`docs/implementation-plan.en.md`](./docs/implementation-plan.en.md) — plan
  de integración y matriz de capacidades.
- [`docs/hackathon/`](./docs/hackathon/) — bases, reglamento y material de
  investigación del Hackathon CyberAr.
- [`docs/SANDBOX.md`](./docs/SANDBOX.md) — límites del worker de evidencia.

## Referencias de diseño

Zaynor se está componiendo a partir de tres repositorios existentes y toma
patrones concretos de proyectos relacionados. Las referencias no otorgan
autoridad al LLM ni sustituyen el contrato local del proyecto:

- **VIGÍA:** motor matemático determinista, veredictos, sellado y modelo de
  evidencia read-only.
- **ANNACONDA:** separación entre hechos autorizados y narrativa, además del
  loop acotado de investigación.
- **Forge:** estructura de reporte y separación entre explicación para junior
  y análisis técnico.
- **K8sGPT:** separación entre hallazgo estructurado y explicación generada.
- **HolmesGPT:** investigación iterativa con herramientas y presupuesto de
  pasos.
- **Keep:** separación entre identidad de evento, fingerprint de alerta e
  identidad de incidente.

Los componentes de terceros y las adaptaciones se mantienen sujetos a sus
licencias y se documentan antes de la entrega final.

## Licencia

Apache License 2.0 — ver [`LICENSE`](./LICENSE).
