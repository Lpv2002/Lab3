# Lab 6 — Policy as Code con Conftest: resumen

## Identificación

- Repositorio: https://github.com/Lpv2002/Lab3
- Rama: `lab/guias-devsecops-local`
- Herramienta: `openpolicyagent/conftest:latest`, Conftest v0.71.1 (OPA 1.21.1)
  - Digest: `sha256:0e77cdf7c1fcde035f3c579e4aaa6664ee2a8be5777eaa9af9f520cdd02280c0`
- Archivo evaluado: `compose-lab.yaml`
- Política: `policy/compose.rego` (Rego v1, paquete `main`)
- Fecha de ejecución: 9 de octubre de 2026 (antes 21:24, después 21:25)

## Política

```rego
deny contains msg if {
    some name, service in input.services
    service.privileged == true
    msg := sprintf("Servicio %s: privileged=true no permitido", [name])
}
```

Recorre todos los servicios del archivo Compose y agrega un mensaje a `deny` por cada
uno que declare `privileged: true`. Conftest falla si `deny` contiene algún mensaje.

## Resultado

| Momento | `privileged` | Resultado | Código de salida |
|---|---|---|---|
| Antes | `true` | 1 test, 0 aprobados, 1 fallo | 1 |
| Después | `false` | 1 test, 1 aprobado, 0 fallos | 0 |

Mensaje del fallo inicial:

```text
FAIL - compose-lab.yaml - main - Servicio app: privileged=true no permitido
```

## Riesgo

Un contenedor con `privileged: true` recibe todas las capacidades del kernel y acceso
a los dispositivos del host. Si se compromete el proceso del contenedor, el atacante
puede montar el sistema de archivos del host o cargar módulos y salir del
aislamiento. Para servir contenido con nginx no hace falta ningún privilegio.

## Corrección

Se cambió `privileged: true` por `privileged: false` en `compose-lab.yaml`. El
servicio no se inició: la evaluación es sobre el archivo, antes de cualquier
despliegue.

## Pasar la regla no es lo mismo que estar seguro

La política comprueba una sola condición. El archivo corregido la aprueba, pero
Conftest no dice nada sobre lo que la política no pregunta:

- el usuario con el que corre el proceso (nginx arranca como root por defecto);
- capacidades añadidas con `cap_add` o el uso de `network_mode: host`;
- volúmenes que monten rutas sensibles del host, como el socket de Docker;
- puertos publicados en todas las interfaces;
- la imagen: `nginx:stable` es un tag mutable y puede tener vulnerabilidades (Lab 3).

Un resultado "1 passed" significa que no se violó esta regla, no que la configuración
sea segura. Para ampliar la cobertura hay que agregar reglas por cada control y
combinar la política con el escaneo de imágenes.

## Evidencia

- `compose-lab.yaml` y `policy/compose.rego`
- `reports/conftest-before.json` y `reports/conftest-after.json`
- `reports/logs/lab6-conftest-antes.txt` y `lab6-conftest-despues.txt` (salida de
  terminal con hora de inicio y código de salida)
