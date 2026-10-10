# Lab 4 — SBOM Maven con CycloneDX y SCA con Trivy: resumen

## Identificación

- Repositorio: https://github.com/Lpv2002/Lab3
- Rama: `lab/guias-devsecops-local`
- Commit anterior: `103fc9d` (`commons-text` 1.9)
- Commit posterior: `57cb852` (`commons-text` 1.10.0)
- SBOM: `cyclonedx-maven-plugin` 2.9.3, goal `makeAggregateBom`, CycloneDX 1.6 en JSON,
  sin dependencias de alcance `test`
- SCA: `aquasec/trivy:0.74.0`, comando `sbom --scanners vuln`
- Entorno: Maven 3.9.16, Spring Boot 3.5.14
- Fecha de ejecución: 9 de octubre de 2026 (antes 21:34 a 21:48, después 21:49 a 21:53)

## Inventario (paso 4)

`target/bom.json` describe 53 componentes.

| Elemento | Nombre y versión | `purl` |
|---|---|---|
| Aplicación (`metadata.component`) | `springboot-devsecops-lab` 1.0.0 | `pkg:maven/bo.edu.devsecops/springboot-devsecops-lab@1.0.0?type=jar` |
| Dependencia directa | `commons-text` 1.9 | `pkg:maven/org.apache.commons/commons-text@1.9?type=jar` |
| Dependencia transitiva | `commons-lang3` 3.17.0 | `pkg:maven/org.apache.commons/commons-lang3@3.17.0?type=jar` |

`commons-text` está declarada en el `pom.xml`; `commons-lang3` no lo está y llega a
través de ella, como muestran tanto `mvn dependency:tree` como la sección
`dependencies` del SBOM. El árbol tiene más componentes que el `pom.xml` porque cada
*starter* de Spring Boot arrastra sus propias dependencias.

## Hallazgo seleccionado

| Campo | Antes | Después |
|---|---|---|
| Componente | `org.apache.commons:commons-text` | `org.apache.commons:commons-text` |
| Versión resuelta | 1.9 | 1.10.0 |
| CVE | CVE-2022-42889 | — |
| Severidad | CRITICAL (CVSS 9.8) | — |
| Versión corregida indicada por Trivy | 1.10.0 | — |
| Presencia del hallazgo | Sí | No |
| Tipo de dependencia | Directa | Directa |

CVE-2022-42889 ("Text4Shell") permite ejecución remota de código cuando se interpola
con `StringSubstitutor` una cadena controlada por un atacante. En este proyecto la
biblioteca está declarada pero ninguna clase de `src/` la utiliza, de modo que el
hallazgo es una versión afectada presente, no una vulnerabilidad explotable
demostrada. No se ejecutó ninguna explotación.

## Cambio realizado

En `pom.xml`, la versión de `commons-text` pasó de `1.9` a `1.10.0`. Al ser una
dependencia directa con versión explícita, bastó con editar esa línea; no hizo falta
tocar el parent de Spring Boot.

`1.10.0` es la corrección histórica mínima de esta CVE, no la versión vigente de la
biblioteca. Como la dependencia se agregó solo para el laboratorio y el código no la
usa, eliminarla sería una remediación igual de válida.

## Pruebas ejecutadas

| Momento | Comando | Resultado |
|---|---|---|
| Antes | `mvn -B clean verify` | 2 pruebas, 0 fallos, `BUILD SUCCESS` |
| Después | `mvn -B clean verify` | 2 pruebas, 0 fallos, `BUILD SUCCESS` |

## Comparación de los reportes

| Severidad | `sca-before.json` | `sca-after.json` |
|---|---|---|
| CRITICAL | 9 | 8 |
| HIGH | 16 | 16 |
| MEDIUM | 23 | 23 |
| LOW | 5 | 5 |
| **Total** | **53** | **52** |

La única diferencia entre ambos reportes es CVE-2022-42889 en `commons-text` 1.9, que
desaparece. No aparece ningún hallazgo nuevo. Los dos SBOM tienen 53 componentes y
solo difieren en la versión de `commons-text`.

## Hallazgos pendientes

Quedan 52 hallazgos, todos en dependencias transitivas administradas por Spring Boot
3.5.14:

| Componente | Versión | Hallazgos | Severidad máxima |
|---|---|---|---|
| `tomcat-embed-core` | 10.1.54 | 10 | CRITICAL |
| `spring-webmvc` | 6.2.18 | 10 | CRITICAL |
| `jackson-databind` | 2.21.2 | 16 | HIGH |
| `jackson-core` | 2.21.2 | 3 | HIGH |
| `spring-expression` | 6.2.18 | 3 | HIGH |
| `micrometer-core` | 1.15.11 | 2 | HIGH |
| otros (`spring-web`, `spring-core`, `spring-security-web`, `spring-boot-autoconfigure`, `logback-core`, `log4j-api`, `commons-lang3`) | — | 8 | MEDIUM |

La vía recomendada es actualizar el parent de Spring Boot a la versión de parche
siguiente (3.5.15 o posterior), que eleva en conjunto Tomcat, Spring Framework,
Jackson y Micrometer, en lugar de sobrescribir versiones una por una. Dos CRITICAL de
`spring-webmvc` (CVE-2026-47884 y CVE-2026-47890) solo indican corrección en la línea
7.0.x, lo que exige evaluar una migración mayor. Esa actualización queda fuera del
alcance de este laboratorio.

## Limitaciones

- El SBOM excluye el alcance `test` y no describe la imagen base ni el sistema
  operativo; eso lo cubre el Lab 3.
- Trivy advierte que analizar un SBOM de terceros puede ser menos preciso que uno
  generado por la propia herramienta.
- Los resultados dependen de la base de vulnerabilidades del día del análisis.

## Evidencia

- `reports/sbom/bom-before-103fc9d.json` y `reports/sbom/bom-after-57cb852.json`
- `reports/sca-before.json` y `reports/sca-after.json`
- `reports/logs/lab4-*.txt` (árbol de dependencias, compilación, generación del SBOM y
  escaneos, con hora de inicio y código de salida)
