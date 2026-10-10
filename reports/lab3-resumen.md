# Lab 3 — Escaneo de imágenes con Trivy: resumen

## Identificación

- Repositorio: https://github.com/Lpv2002/Lab3
- Rama: `lab/guias-devsecops-local`
- Herramienta: `aquasec/trivy:0.74.0`, con `--image-src remote --scanners vuln`
- Caché: volumen Docker `trivy-cache`
- Fecha de ejecución: 9 de octubre de 2026 (21:46 a 21:48, hora local)

| Imagen | Sistema base | Digest analizado |
|---|---|---|
| `nginx:1.24.0` | Debian 11.9 (sin soporte) | `sha256:f6daac2445b0ce70e64d77442ccf62839f3f1b4c24bf6746a857eff014e798c8` |
| `nginx:stable` (nginx 1.30.5) | Debian 13.7 | `sha256:9bf97bd7714f5e24c1ccd545ecb9eb5435cb6d109c97cebb15e7e455e0239edb` |

## Resultado

| Severidad | `nginx:1.24.0` | `nginx:stable` |
|---|---|---|
| CRITICAL | 17 | 1 |
| HIGH | 175 | 69 |
| MEDIUM | 300 | 109 |
| LOW | 238 | 124 |
| UNKNOWN | 17 | 27 |
| **Total** | **747** | **330** |
| CVE distintas | 466 | 177 |

Trivy advierte que Debian 11.9 ya no recibe actualizaciones de seguridad, por lo que
la detección sobre `nginx:1.24.0` puede incluso quedarse corta.

## Control HIGH/CRITICAL

El comando con `--severity HIGH,CRITICAL --exit-code 1` terminó con código de salida
**1** y dejó la tabla en `trivy-gate.txt`:

```text
Total: 192 (HIGH: 175, CRITICAL: 17)
```

El control bloquea la imagen antigua, que es el comportamiento esperado.

## CVE seleccionadas

| Campo | CVE-2024-45491 | CVE-2024-2961 |
|---|---|---|
| Paquete | `libexpat1` | `libc6` |
| Severidad | CRITICAL (CVSS 9.8) | HIGH (CVSS 8.8) |
| Descripción | Desbordamiento de entero en libexpat | Escritura fuera de límites en `iconv` de glibc; puede llevar a ejecución remota de código |
| Versión instalada | `2.2.10-2+deb11u5` | `2.31-13+deb11u8` |
| Versión corregida | `2.2.10-2+deb11u6` | `2.31-13+deb11u9` |
| En `nginx:stable` | No aparece (`libexpat1` 2.8.3) | No aparece (`libc6` 2.41) |

## Cambio propuesto

Reemplazar la base `nginx:1.24.0` por `nginx:stable`, fijada por digest para que el
resultado sea reproducible:

```dockerfile
FROM nginx@sha256:9bf97bd7714f5e24c1ccd545ecb9eb5435cb6d109c97cebb15e7e455e0239edb
```

El cambio actualiza a la vez nginx (1.24.0 a 1.30.5) y el sistema base (Debian 11 a
Debian 13), que es de donde proviene la mayor parte de los hallazgos.

## Resultado de la comparación

- Las dos CVE seleccionadas desaparecen en `nginx:stable`.
- El total baja de 747 a 330 (un 56 % menos) y las CRITICAL de 17 a 1.

## Hallazgos pendientes

`nginx:stable` no está libre de vulnerabilidades:

- Queda 1 CRITICAL: CVE-2026-6653 en `libxml2`, con estado `affected` y sin versión
  corregida publicada.
- Quedan 69 HIGH. Ninguno de los hallazgos HIGH o CRITICAL tiene versión corregida
  disponible, así que actualizar paquetes no los resuelve hoy.
- El mismo control HIGH/CRITICAL seguiría fallando sobre `nginx:stable`.

Acciones para lo pendiente: repetir el escaneo cuando Debian publique las
correcciones, valorar una imagen con menos paquetes (por ejemplo una variante
`alpine` o `slim`) para reducir la superficie, y revisar si las bibliotecas afectadas
se usan en la configuración real antes de aceptar el riesgo.

## Aplicación al proyecto

El `Dockerfile` del proyecto no usa nginx, sino `eclipse-temurin:21-jdk-alpine`, así
que el cambio de base no se aplicó al código. El laboratorio se realizó sobre las
imágenes de referencia que indica la guía.

## Incidencia durante la ejecución

El primer intento del paso 3 terminó con un error de tiempo de espera: Trivy tuvo que
descargar por primera vez su base de vulnerabilidades (120 MB) y la base de Java
(935 MB), y el análisis superó el límite predeterminado. Con las bases ya en el
volumen `trivy-cache`, el mismo comando se repitió sin cambios y terminó
correctamente. Los reportes entregados corresponden a esa segunda ejecución.

## Evidencia

- `reports/trivy-before.json`, `reports/trivy-after.json` y `reports/trivy-gate.txt`
- `reports/logs/lab3-trivy-before.txt`, `lab3-trivy-gate.txt` y `lab3-trivy-after.txt`
  (salida de terminal con hora de inicio y código de salida)
