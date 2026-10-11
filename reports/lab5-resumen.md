# Lab 5 — Detección de secretos con Gitleaks: resumen

## Identificación

- Repositorio: https://github.com/Lpv2002/Lab3
- Rama: `lab/guias-devsecops-local`
- Herramienta: `ghcr.io/gitleaks/gitleaks:latest`, versión v8.30.1
  - Digest: `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`
- Fecha de ejecución: 9 de octubre de 2026 (antes 21:27, después 21:28, historial 21:28)

## Preparación

Regla didáctica en `.gitleaks-demo.toml`, que extiende las reglas predeterminadas:

```toml
title = "Regla didactica"
[extend]
useDefault = true

[[rules]]
id = "demo-token"
description = "Token ficticio del laboratorio"
regex = '''DEMO_TOKEN_[A-Z0-9]{16}'''
keywords = ["DEMO_TOKEN_"]
```

Archivo `secret-demo/demo.env` con un valor ficticio que cumple el patrón de la regla.
No se utilizó ninguna credencial real.

## Resultado

| Análisis | Alcance | Hallazgos | Código de salida |
|---|---|---|---|
| `gitleaks-before.json` | carpeta `secret-demo` | 1 | 1 |
| `gitleaks-after.json` | carpeta `secret-demo` | 0 | 0 |
| `gitleaks-history.json` | historial Git, 28 commits (3,84 MB) | 0 | 0 |

### Hallazgo inicial

| Campo | Valor |
|---|---|
| Regla | `demo-token` — Token ficticio del laboratorio |
| Archivo | `secret-demo/demo.env` |
| Línea | 1 (columnas 11 a 37) |
| Valor | `REDACTED` (opción `--redact`) |

El código de salida 1 es el esperado cuando Gitleaks detecta al menos un secreto.

## Mitigación

1. Se reemplazó el valor del archivo por `API_TOKEN=REPLACE_AT_RUNTIME`: el secreto
   deja de estar en el archivo y se inyecta al ejecutar (variable de entorno o gestor
   de secretos).
2. El segundo análisis de la carpeta ya no reporta hallazgos.
3. Los archivos de demostración (`secret-demo/` y `.gitleaks-demo.toml`) no se
   incluyeron en ningún commit y se retiraron al terminar.

Si el valor hubiera sido una credencial real, el orden correcto es revocarla o
rotarla primero y después tratar su exposición en Git: borrar la línea del archivo
actual no la elimina de los commits anteriores.

## Archivo actual frente a historial

- El análisis `dir` revisa solo el contenido presente de una carpeta. Por eso el token
  de demostración desaparece al editar el archivo.
- El análisis `git` recorre los 28 commits del repositorio. Si el token se hubiera
  confirmado en un commit, seguiría apareciendo en este análisis aunque el archivo
  actual estuviera limpio.

## Limitaciones observadas

El historial no reportó hallazgos con las reglas predeterminadas, pero eso no
significa que el repositorio no contenga secretos:

- `AuthController.java` tiene constantes con una contraseña y un secreto JWT escritos
  en el código. Semgrep los señala con la regla `lab-hardcoded-secret` del
  repositorio; las reglas predeterminadas de Gitleaks no los detectaron.
- `pom.xml` contiene el valor de `nvdApiKey` en claro, heredado del repositorio de
  trabajo original. Tampoco fue detectado, porque no coincide con el formato de
  ningún proveedor conocido.

Gitleaks reconoce formatos de credenciales concretos y cadenas con alta entropía
junto a ciertas palabras clave. Para cubrir casos como estos hacen falta reglas
propias, igual que la regla `demo-token` de este laboratorio.

## Evidencia

- `reports/gitleaks-before.json`, `reports/gitleaks-after.json` y
  `reports/gitleaks-history.json` (valores redactados)
- `reports/logs/lab5-gitleaks-antes.txt`, `lab5-gitleaks-despues.txt` y
  `lab5-gitleaks-historial.txt` (salida de terminal con hora de inicio y código de
  salida)
