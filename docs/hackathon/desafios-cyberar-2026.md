# HACKATHON CYBER.AR 2026 — Bases técnicas y desafíos

> Source: `Hackathon_CyberAr_2026_Desafios.pdf` ("Ficha Técnica Oficial").
> Verbatim transcription kept in Spanish (original language of the official
> challenge bases) for fidelity to the source document. This is reference
> material for the team working on the hackathon project, not
> repository-authored documentation.
>
> **Equipo `zaynor`: elegimos el Eje 2 — Inteligencia artificial para la
> defensa de redes e infraestructura.**

"La Ciberdefensa necesita de todos"

Bases técnicas del Hackathon Nacional de Ciberdefensa

## Marco general

El Hackathon Nacional de Ciberdefensa CYBER.AR 2026 se estructura en tres ejes
temáticos. Cada equipo deberá seleccionar un eje y definir, dentro de él, un
problema concreto, su alcance y la solución que desarrollará durante las
**48 horas**.

Las líneas de proyecto incluidas en estas bases son **orientativas y no
excluyentes**. No se exige resolver todas las propuestas de un eje: se
priorizarán la pertinencia del problema elegido, la calidad de la
implementación y su potencial de adopción real.

## Condiciones comunes

- **Tipo de solución.** La propuesta deberá ser exclusivamente de software y
  culminar en una demostración funcional al cierre de las **48 horas**. Cada
  equipo podrá definir libremente el problema específico dentro del eje
  seleccionado.
- **Datos y entornos autorizados.** Solo podrán utilizarse datos simulados o
  de acceso público. Queda prohibido realizar pruebas sobre sistemas reales.
- **Soberanía tecnológica.** Toda solución que incorpore inteligencia
  artificial deberá poder ejecutarse en infraestructura propia, sin enviar
  datos a servicios externos. Se permite el uso de modelos abiertos y
  herramientas de código abierto.
- **Entregables.** Cada equipo deberá presentar un repositorio con el código
  fuente y un archivo README que dispondrá según indicaciones del comité
  organizador, una presentación de **3 minutos** que integre el pitch y la
  demostración funcional. La presentación deberá exponer el problema, la
  solución desarrollada y una posible estrategia de adopción real.

## Eje 1 — Sistemas autónomos y no tripulados

### Contexto

Los drones y los vehículos autónomos son componentes centrales de los
conflictos actuales. Su funcionamiento depende de sistemas de
posicionamiento, enlaces de radio, sensores, redes internas y modelos de
inteligencia artificial, todos ellos susceptibles de interferencia, engaño o
ataque.

### Objetivo

Desarrollar software que incremente la confiabilidad, resiliencia y capacidad
de operación segura de un sistema autónomo frente a ataques o condiciones
adversas.

### Posibles líneas de proyecto

- Detección de falsificación de señales GPS mediante su comparación con el
  resto de la telemetría.
- Detección de ataques o anomalías en la red interna de un vehículo basada en
  bus CAN (Controller Area Network).
- Definición y simulación de un comportamiento seguro ante la pérdida o
  degradación del enlace de comunicaciones.
- Evaluación y mejora de la robustez de un modelo de reconocimiento frente a
  imágenes alteradas o ataques adversariales.

## Eje 2 — Inteligencia artificial para la defensa de redes e infraestructura

> **Eje elegido por el equipo `zaynor`.**

### Contexto

La creciente integración de sistemas digitales en el ámbito de la defensa
plantea nuevos desafíos para la protección de redes, servicios e información.
La inteligencia artificial ofrece oportunidades para apoyar el análisis de
eventos, facilitar la detección temprana de amenazas y asistir a los equipos
técnicos en la toma de decisiones. Este eje propone desarrollar soluciones
orientadas a las necesidades reales, con énfasis en la ejecución en
infraestructura propia, el control de los datos y la confiabilidad de los
sistemas.

### Objetivo

Desarrollar herramientas basadas en inteligencia artificial que permitan
detectar, priorizar y responder ante ataques, con capacidad de ejecución
local y resistencia frente a intentos de manipulación.

### Posibles líneas de proyecto

- Asistente en español para resumir, clasificar y priorizar alertas de
  seguridad.
- Correlación de eventos para reconstruir la secuencia de un ataque.
- Monitor de la red industrial de una base ficticia, incluyendo energía, agua
  y control de accesos.
- Inventario automático del software utilizado por el equipamiento y
  correlación con vulnerabilidades conocidas registradas como CVE (Common
  Vulnerabilities and Exposures).

## Eje 3 — Entrenamiento y simulación de ciberdefensa

### Contexto

La formación de especialistas en ciberdefensa requiere tiempo, práctica
continua y entornos seguros. Además, todo el personal necesita incorporar
nociones básicas que le permitan reconocer amenazas y actuar correctamente
ante incidentes.

### Objetivo

Desarrollar herramientas, simuladores o ejercicios que puedan continuar
utilizándose y ampliándose después del hackathon para la capacitación del
personal.

### Posibles líneas de proyecto

- Ejercicios de tipo captura la bandera (CTF – Capture The Flag) basados en
  escenarios militares.
- Simulador de incidentes en el que el alumno tome decisiones y observe sus
  consecuencias.
- Atacante simulado mediante inteligencia artificial que genere escenarios
  diferentes en cada ejercicio.
- Entrenador para personal no técnico sobre phishing y uso seguro de
  dispositivos móviles.
- Tablero para que el instructor supervise el desempeño y la evolución de los
  participantes.

### Restricción específica

Todo componente ofensivo deberá funcionar **exclusivamente dentro de un
entorno de entrenamiento aislado**.

## Jurado y presentación final

### Composición del jurado

El jurado estará integrado por profesionales civiles y militares, con
especialistas en inteligencia artificial, criptografía y ciberseguridad. Su
evaluación combinará la perspectiva técnica con la pertinencia de las
propuestas para el ámbito de la defensa.

### Pitch y demostración funcional

El pitch y la demostración funcional serán elementos centrales de la
evaluación. El representante del equipo, en el día/lugar/horario determinado
por el comité organizador, deberá explicar con claridad el problema
abordado, mostrar el funcionamiento de la solución y justificar su posible
aplicación.

La exposición deberá priorizar el aporte a la ciberseguridad y, cuando
corresponda, el uso de inteligencia artificial, explicando su función y su
valor dentro de la solución. El contenido deberá resultar comprensible para
los distintos perfiles del jurado.

### Duración y dinámica

**Recordar, importante.** Cada presentación dispondrá de **3 minutos** en
total para el pitch y la demostración funcional, seguidos de **1 minuto**
para preguntas del jurado y respuestas. Ambos componentes de la presentación
deberán organizarse dentro del tiempo asignado.

## Consideraciones finales

Los equipos deberán justificar la **relevancia del problema elegido para el
entorno de la soberanía y ciberdefensa** y explicar de qué manera la solución
podría integrarse, mantenerse y ampliarse después del hackathon. La
organización podrá ajustar o complementar los recursos provistos sin
modificar el propósito general de cada eje.

---

*Hackathon CyberAr 2026 – Casos de Ciberdefensa | Ficha Técnica Oficial*
