# Lab 2 — DAST baseline con OWASP ZAP y Juice Shop: resumen

## Identificación

- Repositorio: https://github.com/Lpv2002/Lab3
- Rama: `lab/guias-devsecops-local`
- Objetivo: OWASP Juice Shop (`bkimminich/juice-shop:latest`), en la red Docker
  `devsecops-lab` y publicado solo en `127.0.0.1:3000`
  - Digest: `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`
- Herramienta: `ghcr.io/zaproxy/zaproxy:stable`, ZAP 2.17.0, script `zap-baseline.py`
  - Digest: `sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2`
- Parámetros: `-t http://juice-shop:3000 -m 1 -T 5` (spider de 1 minuto, espera máxima
  de 5 minutos para el análisis pasivo)
- Fecha de ejecución: 9 de octubre de 2026, 20:49 (hora local)

## Resultado

| FAIL | WARN | PASS | URLs exploradas | Código de salida |
|---|---|---|---|---|
| 0 | 8 | 59 | 88 | 2 (WARN sin FAIL) |

El reporte contiene 11 alertas: 2 de riesgo Medium, 5 Low y 4 informativas. El
resumen de consola agrupa por regla, por eso muestra 8 WARN: la regla 90004 produce
dos alertas (COEP y COOP) y la 10049 produce tres variantes informativas.

| Riesgo | Alerta | Regla | Instancias |
|---|---|---|---|
| Medium | Content Security Policy (CSP) Header Not Set | 10038 | 5 |
| Medium | Cross-Domain Misconfiguration | 10098 | 5 |
| Low | Cross-Origin-Embedder-Policy Header Missing or Invalid | 90004 | 5 |
| Low | Cross-Origin-Opener-Policy Header Missing or Invalid | 90004 | 5 |
| Low | Dangerous JS Functions | 10110 | 1 |
| Low | Deprecated Feature Policy Header Set | 10063 | 5 |
| Low | Timestamp Disclosure - Unix | 10096 | 5 |
| Informational | Modern Web Application | 10109 | 5 |
| Informational | Non-Storable Content | 10049 | 3 |
| Informational | Storable and Cacheable Content | 10049 | 2 |
| Informational | Storable but Non-Cacheable Content | 10049 | 5 |

## Alertas seleccionadas

### 1. Content Security Policy (CSP) Header Not Set — Medium

- **URL:** `http://juice-shop:3000` (también `/ftp`, `/sitemap.xml` y otras)
- **Evidencia:** la respuesta no incluye la cabecera `Content-Security-Policy`.
- **Riesgo:** sin CSP el navegador no restringe el origen de scripts, estilos ni
  marcos, por lo que un XSS se explota sin ninguna barrera adicional (CWE-693).
- **Solución sugerida por ZAP:** configurar el servidor para enviar la cabecera.
- **Mitigación propuesta:** en la aplicación Express, definir la política con
  `helmet.contentSecurityPolicy`, empezando por `default-src 'self'` y abriendo solo
  los orígenes necesarios.

### 2. Cross-Domain Misconfiguration — Medium

- **URL:** `http://juice-shop:3000` (también `/polyfills.js`, `/scripts.js`,
  `/robots.txt`, `/sitemap.xml`)
- **Evidencia:** `Access-Control-Allow-Origin: *`
- **Riesgo:** cualquier sitio puede leer desde el navegador las respuestas que no
  requieren autenticación (CWE-264).
- **Solución sugerida por ZAP:** restringir `Access-Control-Allow-Origin` a un
  conjunto de dominios de confianza o retirar CORS.
- **Mitigación propuesta:** configurar el middleware `cors` con una lista explícita
  de orígenes en lugar del comodín.

### 3. Dangerous JS Functions — Low

- **URL:** `http://juice-shop:3000/main.js`
- **Evidencia:** `bypassSecurityTrustHtml(`
- **Riesgo:** la función desactiva el saneamiento de HTML de Angular; si recibe datos
  controlados por el usuario, produce XSS en el DOM (CWE-749).
- **Solución sugerida por ZAP:** revisar el uso de la función según las referencias.
- **Mitigación propuesta:** eliminar las llamadas a `bypassSecurityTrustHtml` sobre
  datos de usuario y dejar que Angular sanee el contenido.

## Configuración frente a lógica de negocio

- **Alertas de configuración (9 de 11):** cabeceras ausentes u obsoletas (CSP, COEP,
  COOP, `Feature-Policy`), CORS abierto y directivas de caché. Se corrigen en la
  configuración del servidor o de un proxy, sin tocar la lógica de la aplicación.
- **Alertas ligadas al código (2 de 11):** *Dangerous JS Functions* y *Timestamp
  Disclosure* señalan contenido del código servido. Son indicios que requieren
  revisión manual, no vulnerabilidades confirmadas.
- **Lo que el baseline no encontró:** ninguna de las vulnerabilidades de lógica de
  negocio conocidas de Juice Shop (inyección SQL en el inicio de sesión, control de
  acceso roto, manipulación de la cesta). El baseline solo observa respuestas; no
  envía ataques ni inicia sesión.

## Rutas exploradas y rutas que faltan

- **Exploradas (88 URLs):** la página inicial, los recursos estáticos (`main.js`,
  `polyfills.js`, `scripts.js`, `styles.css`), `robots.txt`, `sitemap.xml` y el
  directorio `/ftp` con sus archivos, descubierto a partir de `robots.txt`.
- **No exploradas:** las vistas de la SPA Angular, que se cargan con rutas `#/...` que
  el spider tradicional no ejecuta; la API REST (`/rest/...`, `/api/...`), a la que
  solo se llega ejecutando JavaScript; y todo lo que requiere autenticación.
- **Para ampliar la cobertura:** usar el spider AJAX (`-j`), importar la definición de
  la API o configurar un contexto autenticado, y ejecutar un escaneo activo en un
  entorno autorizado.

## Remediación

Juice Shop es un objetivo deliberadamente vulnerable y de terceros: las correcciones
quedan documentadas como propuesta y no se modificó el contenedor.

## Evidencia

- `reports/zap-report.html` y `reports/zap-report.json`
- `reports/zap.yaml` (plan de automatización generado por `zap-baseline.py`)
- `reports/logs/lab2-zap-baseline.txt` (salida de terminal con hora de inicio y
  código de salida)
