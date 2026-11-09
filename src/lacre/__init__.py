"""lacre — libro de evidencia a prueba de manipulación. Cero dependencias.

Cadena de hashes + árbol de Merkle (RFC 6962/9162) sobre un JSONL de solo-anexar,
con afirmaciones que caducan cuando cambia la evidencia de la que dependen.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

__version__ = "0.2.0"
__all__ = [
    "Libro", "LacreError", "LibroCorrupto",
    "raiz_merkle", "verificar_inclusion", "verificar_consistencia", "comprobar",
    "VIGENTE", "CADUCA", "HUERFANA", "RELEVADA",
]

VIGENTE, CADUCA, HUERFANA, RELEVADA = "vigente", "caduca", "huerfana", "relevada"
_GRAVEDAD = {VIGENTE: 0, CADUCA: 1, HUERFANA: 2}
_CERO = "0" * 64


class LacreError(Exception):
    """Error de uso del libro."""


class LibroCorrupto(LacreError):
    """El libro no supera la verificación de integridad."""


# ── primitivas ────────────────────────────────────────────────────────────────

def _canon(obj: Any) -> bytes:
    """JSON canónico: claves ordenadas, sin espacios, sin NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _hoja(b: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + b).digest()


def _nodo(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _sha_archivo(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for trozo in iter(lambda: f.read(1 << 20), b""):
            h.update(trozo)
    return h.hexdigest()


# ── Merkle (RFC 6962 §2.1) ────────────────────────────────────────────────────

def _k(n: int) -> int:
    """Mayor potencia de 2 estrictamente menor que n (n ≥ 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(h: Sequence[bytes], lo: int, hi: int) -> bytes:
    n = hi - lo
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return h[lo]
    k = _k(n)
    return _nodo(_mth(h, lo, lo + k), _mth(h, lo + k, hi))


def _camino(m: int, h: Sequence[bytes], lo: int, hi: int) -> list[bytes]:
    n = hi - lo
    if n == 1:
        return []
    k = _k(n)
    if m < k:
        return _camino(m, h, lo, lo + k) + [_mth(h, lo + k, hi)]
    return _camino(m - k, h, lo + k, hi) + [_mth(h, lo, lo + k)]


def _sub(m: int, h: Sequence[bytes], lo: int, hi: int, b: bool) -> list[bytes]:
    n = hi - lo
    if m == n:
        return [] if b else [_mth(h, lo, hi)]
    k = _k(n)
    if m <= k:
        return _sub(m, h, lo, lo + k, b) + [_mth(h, lo + k, hi)]
    return _sub(m - k, h, lo + k, hi, False) + [_mth(h, lo, lo + k)]


def raiz_merkle(hojas: Sequence[bytes]) -> bytes:
    """Raíz del árbol sobre hojas ya hasheadas."""
    return _mth(hojas, 0, len(hojas))


def verificar_inclusion(i: int, n: int, hoja: bytes,
                        camino: Sequence[bytes], raiz: bytes) -> bool:
    """¿La hoja i pertenece al árbol de tamaño n con esa raíz? (RFC 9162 §2.1.3.2)"""
    if not 0 <= i < n:
        return False
    fn, sn, r = i, n - 1, hoja
    for p in camino:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _nodo(p, r)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            r = _nodo(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and hmac.compare_digest(r, raiz)


def verificar_consistencia(m: int, n: int, camino: Sequence[bytes],
                           raiz_m: bytes, raiz_n: bytes) -> bool:
    """¿El árbol de tamaño n extiende al de tamaño m sin reescribirlo? (RFC 9162 §2.1.4.2)"""
    if not 0 <= m <= n:
        return False
    if m == n:
        return not camino and hmac.compare_digest(raiz_m, raiz_n)
    if m == 0:
        return not camino
    c = list(camino)
    if m & (m - 1) == 0:
        c.insert(0, raiz_m)
    if not c:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = c[0]
    for p in c[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _nodo(p, fr), _nodo(p, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = _nodo(sr, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and hmac.compare_digest(fr, raiz_m) and hmac.compare_digest(sr, raiz_n)


def comprobar(prueba: dict) -> bool:
    """Verifica sin el libro una prueba emitida por Libro.probar o Libro.extiende."""
    try:
        camino = [bytes.fromhex(x) for x in prueba["camino"]]
        if prueba["tipo"] == "inclusion":
            return verificar_inclusion(prueba["i"], prueba["n"], bytes.fromhex(prueba["id"]),
                                       camino, bytes.fromhex(prueba["raiz"]))
        if prueba["tipo"] == "consistencia":
            return verificar_consistencia(prueba["m"], prueba["n"], camino,
                                          bytes.fromhex(prueba["raiz_m"]),
                                          bytes.fromhex(prueba["raiz_n"]))
    except (KeyError, ValueError, TypeError):
        pass
    return False


# ── libro ─────────────────────────────────────────────────────────────────────

def _relevados(asientos: list[dict]) -> set[str]:
    return {a["c"]["retira"] for a in asientos if a["tipo"] == "relevo"}


def _id(a: dict) -> str:
    return _hoja(_canon({k: a[k] for k in ("n", "t", "tipo", "c", "prev")})).hex()


class Libro:
    """Libro de evidencia de solo-anexar respaldado por un archivo JSONL.

    ruta: archivo del libro; las rutas de artefactos se guardan relativas a su carpeta.
    clave: secreto opcional para firmar sellos con HMAC-SHA256.
    """

    def __init__(self, ruta: str | os.PathLike, clave: bytes | None = None,
                 reloj: Callable[[], float] = time.time):
        self.ruta = Path(ruta)
        self.base = self.ruta.resolve().parent
        self.clave = clave
        self._reloj = reloj

    # lectura ------------------------------------------------------------------

    def asientos(self) -> list[dict]:
        """Lee y verifica el libro completo; LibroCorrupto si algo no cuadra."""
        if not self.ruta.exists():
            return []
        out: list[dict] = []
        prev = _CERO
        with open(self.ruta, "rb") as f:
            for i, linea in enumerate(f):
                try:
                    a = json.loads(linea)
                    ok = (linea.endswith(b"\n") and a["n"] == i
                          and a["prev"] == prev and a["id"] == _id(a))
                except (ValueError, KeyError, TypeError):
                    ok = False
                if not ok:
                    raise LibroCorrupto(f"asiento {i} inválido en {self.ruta}")
                prev = a["id"]
                out.append(a)
        return out

    def verificar(self) -> int:
        """Devuelve el número de asientos íntegros."""
        return len(self.asientos())

    def __iter__(self) -> Iterator[dict]:
        return iter(self.asientos())

    def buscar(self, ref: str, asientos: list[dict] | None = None) -> dict:
        """Resuelve un id o prefijo único (≥ 8 hex)."""
        if len(ref) < 8:
            raise LacreError("referencia demasiado corta (mínimo 8 caracteres)")
        hits = [a for a in (asientos if asientos is not None else self.asientos())
                if a["id"].startswith(ref)]
        if len(hits) != 1:
            raise LacreError(f"referencia {'ambigua' if hits else 'desconocida'}: {ref}")
        return hits[0]

    # escritura ----------------------------------------------------------------

    @contextmanager
    def _cerrojo(self, espera: float = 10.0):
        p = self.ruta.with_name(self.ruta.name + ".lock")
        fin = time.monotonic() + espera
        while True:
            try:
                fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                if time.monotonic() > fin:
                    raise LacreError(f"cerrojo ocupado: {p}") from None
                time.sleep(0.01)
        try:
            yield
        finally:
            os.close(fd)
            os.unlink(p)

    def _anexar(self, tipo: str, cuerpo: Callable[[list[dict]], dict]) -> dict:
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        with self._cerrojo():
            previos = self.asientos()
            a = {"n": len(previos), "t": int(self._reloj()), "tipo": tipo,
                 "c": cuerpo(previos), "prev": previos[-1]["id"] if previos else _CERO}
            a["id"] = _id(a)
            fd = os.open(self.ruta, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, _canon(a) + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
        return a

    def _rel(self, archivo: str | os.PathLike) -> tuple[Path, str]:
        p = Path(archivo).resolve()
        try:
            return p, p.relative_to(self.base).as_posix()
        except ValueError:
            return p, p.as_posix()

    def sellar(self, archivo: str | os.PathLike) -> dict:
        """Registra el contenido actual de un archivo (ruta, sha256, tamaño)."""
        p, rel = self._rel(archivo)
        if not p.is_file():
            raise LacreError(f"no es un archivo: {archivo}")
        c = {"ruta": rel, "sha256": _sha_archivo(p), "bytes": p.stat().st_size}
        return self._anexar("artefacto", lambda _: c)

    def afirmar(self, texto: str, valor: Any = None, deps: Sequence[str] = (),
                cmd: Sequence[str] | None = None, plazo: float = 600.0) -> dict:
        """Registra una afirmación atada a su evidencia.

        deps: ids (o prefijos) de asientos previos de los que depende.
        cmd: argv que se ejecuta ahora (sin shell); se guardan código de salida y sha256 de stdout.
        """
        ejec = self._ejecutar(cmd, plazo) if cmd else None

        def cuerpo(previos: list[dict]) -> dict:
            c: dict[str, Any] = {"texto": texto,
                                 "deps": [self.buscar(d, previos)["id"] for d in deps]}
            if valor is not None:
                c["valor"] = valor
            if ejec:
                c["cmd"] = ejec
            return c

        return self._anexar("afirmacion", cuerpo)

    def relevar(self, ref: str, por: str | None = None, motivo: str = "") -> dict:
        """Retira un asiento superado sin borrarlo: deja de contar en la vigencia.

        por: id del asiento que lo sustituye (informativo; no traslada dependencias).
        """
        def cuerpo(previos: list[dict]) -> dict:
            viejo = self.buscar(ref, previos)
            if viejo["tipo"] == "relevo":
                raise LacreError("un relevo no se puede relevar")
            if viejo["id"] in _relevados(previos):
                raise LacreError(f"ya relevado: {viejo['id'][:12]}")
            c: dict[str, Any] = {"retira": viejo["id"], "motivo": motivo}
            if por is not None:
                nuevo = self.buscar(por, previos)
                if nuevo["id"] == viejo["id"]:
                    raise LacreError("un asiento no se releva a sí mismo")
                c["por"] = nuevo["id"]
            return c

        return self._anexar("relevo", cuerpo)

    def anotar(self, texto: str) -> dict:
        """Registra una nota libre."""
        return self._anexar("nota", lambda _: {"texto": texto})

    def _ejecutar(self, cmd: Sequence[str], plazo: float) -> dict:
        try:
            r = subprocess.run(list(cmd), cwd=self.base, capture_output=True, timeout=plazo)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise LacreError(f"no se pudo ejecutar {list(cmd)}: {e}") from e
        return {"argv": list(cmd), "rc": r.returncode,
                "salida": hashlib.sha256(r.stdout).hexdigest()}

    # vigencia -----------------------------------------------------------------

    def vigencia(self) -> dict[str, str]:
        """Estado de cada asiento: una afirmación hereda el peor estado de sus dependencias.

        Un asiento relevado queda `relevada`; lo que aún dependa de él, `caduca`.
        """
        est: dict[str, str] = {}
        cache: dict[str, str | None] = {}
        todos = self.asientos()
        fuera = _relevados(todos)
        for a in todos:
            c = a["c"]
            if a["id"] in fuera:
                e = RELEVADA
            elif a["tipo"] == "artefacto":
                ruta = c["ruta"]
                if ruta not in cache:
                    p = self.base / ruta
                    cache[ruta] = _sha_archivo(p) if p.is_file() else None
                actual = cache[ruta]
                e = HUERFANA if actual is None else VIGENTE if actual == c["sha256"] else CADUCA
            else:
                e = max((CADUCA if est[d] == RELEVADA else est[d] for d in c.get("deps", ())),
                        key=_GRAVEDAD.__getitem__, default=VIGENTE)
            est[a["id"]] = e
        return est

    def reejecutar(self, ref: str, plazo: float = 600.0) -> bool:
        """Repite el comando de una afirmación; True si código y salida coinciden."""
        c = self.buscar(ref)["c"]
        if "cmd" not in c:
            raise LacreError("la afirmación no tiene comando")
        return self._ejecutar(c["cmd"]["argv"], plazo) == c["cmd"]

    # sellos y pruebas ---------------------------------------------------------

    def _mac(self, s: dict) -> str:
        if self.clave is None:
            raise LacreError("hace falta una clave para firmar o comprobar la firma")
        return hmac.new(self.clave, _canon({k: s[k] for k in ("n", "raiz", "t")}),
                        hashlib.sha256).hexdigest()

    def sello(self) -> dict:
        """Compromiso con el estado actual: {n, raiz, t[, mac]}. Publícalo fuera del libro."""
        hs = [bytes.fromhex(a["id"]) for a in self.asientos()]
        s: dict[str, Any] = {"n": len(hs), "raiz": raiz_merkle(hs).hex(), "t": int(self._reloj())}
        if self.clave is not None:
            s["mac"] = self._mac(s)
        return s

    def verificar_sello(self, s: dict) -> bool:
        """¿El libro actual contiene, intacta, la historia que el sello comprometió?"""
        try:
            hs = [bytes.fromhex(a["id"]) for a in self.asientos()]
            if "mac" in s and not hmac.compare_digest(self._mac(s), s["mac"]):
                return False
            return 0 <= s["n"] <= len(hs) and raiz_merkle(hs[:s["n"]]).hex() == s["raiz"]
        except (KeyError, TypeError, LibroCorrupto):
            return False

    def probar(self, ref: str) -> dict:
        """Prueba de inclusión autocontenida de un asiento (verificable con `comprobar`)."""
        todos = self.asientos()
        a = self.buscar(ref, todos)
        hs = [bytes.fromhex(x["id"]) for x in todos]
        return {"tipo": "inclusion", "i": a["n"], "n": len(hs), "id": a["id"],
                "camino": [x.hex() for x in _camino(a["n"], hs, 0, len(hs))],
                "raiz": raiz_merkle(hs).hex(), "asiento": a}

    def extiende(self, m: int) -> dict:
        """Prueba de consistencia: el libro actual extiende a su prefijo de tamaño m."""
        hs = [bytes.fromhex(a["id"]) for a in self.asientos()]
        n = len(hs)
        if not 0 <= m <= n:
            raise LacreError(f"tamaño fuera de rango: {m} (libro: {n})")
        camino = _sub(m, hs, 0, n, True) if 0 < m < n else []
        return {"tipo": "consistencia", "m": m, "n": n,
                "raiz_m": raiz_merkle(hs[:m]).hex(), "raiz_n": raiz_merkle(hs).hex(),
                "camino": [x.hex() for x in camino]}
