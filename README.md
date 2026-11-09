# lacre

**Libro de evidencia a prueba de manipulación.** Un archivo JSONL de solo-anexar que registra qué mediste, con qué archivos y con qué comando, y te avisa cuando una cifra deja de estar respaldada. Python puro, cero dependencias.

```
$ lacre sellar datos.csv modelo.pt
$ lacre afirmar "accuracy en test" --valor 0.93 --dep 3f9a1c2b --dep 77e0b4aa -- python eval.py
$ lacre vigencia
vigente     0  3f9a1c2b41d0  artefacto   datos.csv  sha256:9c1e0a77b2f4
vigente     1  77e0b4aa90c3  artefacto   modelo.pt  sha256:e41b6d02a8c9
vigente     2  5d2e9f01c7ab  afirmacion  accuracy en test  = 0.93  $ python eval.py

# … alguien reentrena el modelo …

$ lacre vigencia
vigente     0  3f9a1c2b41d0  artefacto   datos.csv  sha256:9c1e0a77b2f4
caduca      1  77e0b4aa90c3  artefacto   modelo.pt  sha256:e41b6d02a8c9
caduca      2  5d2e9f01c7ab  afirmacion  accuracy en test  = 0.93  $ python eval.py
$ echo $?
1
```

## Por qué

Un resultado publicado —un benchmark en un README, una cifra en un paper, un «tests en verde» en un informe— casi nunca dice de qué dependía, y nada avisa cuando eso cambia. `lacre` ata cada afirmación a su evidencia y ofrece tres garantías:

| Garantía | Mecanismo | Qué detecta |
|---|---|---|
| **Integridad** | Cada asiento incluye el hash del anterior | Editar, borrar o reordenar asientos |
| **Compromiso externo** | Sello `{n, raiz}` con raíz de Merkle (RFC 6962) | Truncar el libro o regenerarlo entero |
| **Vigencia** | Las afirmaciones declaran sus dependencias | Una cifra cuyo respaldo cambió o desapareció |

## Instalación

```bash
pip install git+https://github.com/esraderey/lacre
```

Requiere Python ≥ 3.10. No instala nada más.

## Uso

### Línea de comandos

```bash
lacre sellar <archivo>...                  # registra ruta, sha256 y tamaño
lacre afirmar "<texto>" [--valor V] [--dep ID]... [-- comando]
lacre anotar "<texto>"
lacre relevar <id> [--por ID] [--motivo M]   # retira un asiento superado, sin borrarlo
lacre log                                  # lista los asientos
lacre verificar                            # integridad de la cadena
lacre vigencia                             # ¿sigue respaldado lo afirmado?
lacre reejecutar <id>                      # repite el comando y compara
lacre sello                                # emite el compromiso actual
lacre sello --comprobar sello.json         # ¿el libro contiene esa historia?
lacre probar <id>                          # prueba de inclusión
lacre extiende <m>                         # prueba de consistencia
lacre comprobar prueba.json                # verifica una prueba SIN el libro
```

Los `id` admiten prefijos únicos de 8 caracteres o más. El libro por defecto es `./lacre.jsonl`; se cambia con `-l RUTA` o `LACRE_LIBRO`.

| Código de salida | Significado |
|---|---|
| `0` | Bien |
| `1` | Evidencia no vigente, comando que diverge, sello o prueba no válidos |
| `2` | Libro corrupto o error de uso |

`lacre vigencia` sirve tal cual como puerta de CI.

### Python

```python
from lacre import Libro, comprobar

libro = Libro("lacre.jsonl")

datos = libro.sellar("datos.csv")
a = libro.afirmar("80 tests verdes", 80, deps=[datos["id"]], cmd=["pytest", "-q"])

libro.vigencia()[a["id"]]      # "vigente" | "caduca" | "huerfana" | "relevada"
libro.reejecutar(a["id"])      # True si código de salida y stdout coinciden

sello = libro.sello()          # {"n": 2, "raiz": "…", "t": …}
libro.verificar_sello(sello)   # True mientras el libro contenga esa historia

prueba = libro.probar(a["id"])
comprobar(prueba)              # True; no necesita el libro
```

## Conceptos

**Asiento.** Una línea del libro. Cuatro tipos: `artefacto` (un archivo y su hash), `afirmacion` (un texto, un valor opcional, sus dependencias y un comando opcional), `relevo` y `nota`.

**Vigencia.** Un artefacto está `vigente` si el archivo en disco conserva el hash sellado, `caduca` si cambió y `huerfana` si ya no existe. Una afirmación hereda el peor estado de sus dependencias, y las dependencias pueden ser otras afirmaciones: la caducidad se propaga por toda la cadena de derivación. Restaurar el archivo original revalida; para una versión nueva, se sella de nuevo, se vuelve a afirmar y se releva lo anterior.

**Relevo.** El libro nunca se edita, así que lo superado se retira con un asiento nuevo: `relevar` marca un asiento anterior como `relevada`, opcionalmente señalando cuál lo sustituye. Deja de contar en la vigencia, pero sigue en el libro y sigue siendo demostrable. El relevo no traslada dependencias: una afirmación que aún dependa de un asiento relevado queda `caduca` hasta que se vuelva a afirmar sobre el nuevo.

**Comando como evidencia.** Lo que va tras `--` se ejecuta en el momento, sin shell, y se guardan el código de salida y el sha256 de stdout. `reejecutar` lo repite y compara.

**Sello.** El compromiso `{n, raiz, t}` con el estado del libro. Guardado *fuera* del libro —en un commit, en un paper, en un mensaje público— permite demostrar más tarde que la historia no se reescribió. Con `LACRE_CLAVE` definida, el sello lleva además un HMAC-SHA256.

**Pruebas.** `probar` emite una prueba de inclusión: un asiento concreto pertenece al libro de raíz `R`. `extiende` emite una prueba de consistencia: el libro de tamaño `n` extiende, sin tocarlo, al de tamaño `m`. Ambas ocupan O(log n) y se verifican con `comprobar` sin tener el libro.

## Con Git

El patrón recomendado es llevar `lacre.jsonl` y un `lacre.sello.json` en la raíz del repositorio y commitearlos juntos. El historial de Git conserva así cada sello anterior, y un paso de CI puede comprobar en cada push que el libro actual extiende al sello del commit previo:

```bash
git show HEAD^:lacre.sello.json > previo.json && lacre sello --comprobar previo.json
```

## Formato en disco

Una línea de JSON canónico (claves ordenadas, sin espacios) por asiento:

```json
{"c":{"bytes":1024,"ruta":"datos.csv","sha256":"9c1e…"},"id":"3f9a…","n":0,"prev":"0000…","t":1794250000,"tipo":"artefacto"}
```

- `id` = `SHA-256(0x00 ‖ JSON canónico de {n, t, tipo, c, prev})`
- `prev` = `id` del asiento anterior (64 ceros en el primero)
- Raíz de Merkle según RFC 6962 §2.1, tomando cada `id` como hoja ya hasheada; los nodos internos usan el prefijo `0x01`

El formato es legible, apto para `diff` y para control de versiones.

## Límites

- **No prueba que algo sea verdad.** Prueba que no cambió desde que se asentó.
- **Un libro íntegro puede haber sido truncado o regenerado entero.** Solo un sello guardado fuera lo detecta.
- **HMAC no es firma pública.** Autentica ante quien comparte la clave. Para autoría ante terceros, firma el commit.
- **`reejecutar` compara stdout byte a byte.** Un comando no determinista diverge sin que nada esté mal.
- **`afirmar … -- cmd` y `reejecutar` ejecutan comandos.** No re-ejecutes libros que no sean tuyos.
- **El cerrojo es un archivo `.lock`.** Si un proceso muere con él tomado, hay que borrarlo a mano.
- **Cada anexado relee y verifica el libro entero**, O(n). Pensado para miles de asientos, no para millones.

## Desarrollo

```bash
git clone https://github.com/esraderey/lacre && cd lacre
python -m pytest
```

La suite incluye los vectores de referencia de RFC 6962, verificación exhaustiva de pruebas de inclusión y consistencia para todos los tamaños hasta 40 hojas, ataques de manipulación sobre el archivo y escritores concurrentes.

## Licencia

MIT.
