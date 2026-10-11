# Lab 1 — SAST con Semgrep: resumen

## Identificación

- Repositorio: https://github.com/Lpv2002/Lab3
- Rama: `lab/guias-devsecops-local` (commit base `584fd8d`)
- Herramienta: `semgrep/semgrep:latest`, versión 1.179.0
- Digest de la imagen: `sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b`
- Reglas: `p/java` (60 reglas ejecutadas sobre 6 archivos de `src/main/java`)
- Fecha de ejecución: 9 de octubre de 2026 (análisis inicial 19:08, análisis posterior 19:13)

## Resultado

| Reporte | `results` | `errors` |
|---|---|---|
| `semgrep-report.json` (antes) | 3 | 0 |
| `semgrep-after.json` (después) | 1 | 0 |

## Hallazgos revisados

| # | Regla | Archivo:línea | Severidad | CWE | Antes | Después |
|---|---|---|---|---|---|---|
| 1 | `tainted-sql-string` | `ProductController.java:24` | ERROR | CWE-89 | Presente | Corregido |
| 2 | `spring-sqli` | `ProductController.java:25` | WARNING | CWE-89 | Presente | Corregido |
| 3 | `tainted-html-string` | `CommentController.java:19` | ERROR | CWE-79 | Presente | Pendiente |

### 1 y 2. Inyección SQL en la búsqueda de productos

- **Riesgo:** el parámetro HTTP `name` de `GET /api/products/search` se concatenaba
  directamente en la sentencia SQL. Un valor como `' OR '1'='1` altera la consulta.
- **Aplicabilidad:** confirmado. El endpoint es público (`permitAll`) y el valor llega
  sin validación hasta `jdbcTemplate.queryForList(sql)`. Las dos reglas señalan el
  mismo defecto: una en la construcción de la cadena y otra en su ejecución.
- **Corrección:** consulta parametrizada; el comodín `%` se arma en el valor del
  parámetro y no en la sentencia.

  ```java
  return jdbcTemplate.queryForList(
          "SELECT id, name, price FROM products WHERE name LIKE ?", "%" + name + "%");
  ```

- **Verificación:** `mvn test` — 2 pruebas, 0 fallos, `BUILD SUCCESS`. La prueba
  `productSearchIsAvailable` sigue respondiendo 200 con `name=Laptop`.
- **Resultado:** ambos hallazgos desaparecen en `semgrep-after.json`.

### 3. HTML construido con entrada del usuario

- **Riesgo:** `POST /api/comments/preview` inserta el campo `comment` en una respuesta
  `text/html` sin codificarlo, lo que permite XSS reflejado.
- **Aplicabilidad:** confirmado. La respuesta se sirve como HTML y el valor no se escapa.
- **Estado:** no corregido en este laboratorio; la guía pide corregir un hallazgo.
  Corrección propuesta: codificar la salida con `HtmlUtils.htmlEscape(comment)`.

## Alcance y limitaciones

- El análisis usa solo el conjunto comunitario `p/java`. No incluye las reglas propias
  del repositorio (`.semgrep.yml`) ni `--config auto`, que reportan más hallazgos
  (secretos en código, CSRF deshabilitado, `permitAll`).
- Semgrep se limitó a los archivos seguidos por git dentro de `src/main/java`.
- El código de salida fue 0 en ambos análisis: sin `--error`, encontrar hallazgos no
  hace fallar el comando.

## Evidencia

- `reports/semgrep-report.json` y `reports/semgrep-after.json`
- `reports/logs/lab1-scan-antes.txt`, `lab1-mvn-test.txt`, `lab1-scan-despues.txt`
  (salida de terminal con hora de inicio y código de salida)
