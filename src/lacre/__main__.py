"""CLI de lacre. Códigos de salida: 0 bien · 1 evidencia no vigente o prueba falsa · 2 error."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import RELEVADA, VIGENTE, LacreError, Libro, __version__, comprobar


def _valor(s: str | None):
    if s is None:
        return None
    try:
        return json.loads(s)
    except ValueError:
        return s


def _json(o) -> None:
    print(json.dumps(o, ensure_ascii=False, indent=2, sort_keys=True))


def _resumen(a: dict) -> str:
    c = a["c"]
    if a["tipo"] == "artefacto":
        d = f"{c['ruta']}  sha256:{c['sha256'][:12]}"
    elif a["tipo"] == "relevo":
        d = f"retira {c['retira'][:12]}" + (f" → {c['por'][:12]}" if "por" in c else "") \
            + (f"  ({c['motivo']})" if c.get("motivo") else "")
    else:
        d = c["texto"] + (f"  = {json.dumps(c['valor'], ensure_ascii=False)}" if "valor" in c else "")
        if "cmd" in c:
            d += f"  $ {' '.join(c['cmd']['argv'])}"
    return f"{a['n']:>4}  {a['id'][:12]}  {a['tipo']:<10}  {d}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lacre", description="Libro de evidencia a prueba de manipulación.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-l", "--libro", default=os.environ.get("LACRE_LIBRO", "lacre.jsonl"))
    s = p.add_subparsers(dest="orden", required=True)

    x = s.add_parser("sellar", help="registra el contenido de archivos")
    x.add_argument("archivos", nargs="+")
    x = s.add_parser("afirmar", help="registra una afirmación atada a evidencia",
                     epilog="tras `--` va el comando que se ejecuta como evidencia")
    x.add_argument("texto")
    x.add_argument("--valor")
    x.add_argument("--dep", action="append", default=[])
    x = s.add_parser("relevar", help="retira un asiento superado (no lo borra)")
    x.add_argument("ref")
    x.add_argument("--por", help="asiento que lo sustituye")
    x.add_argument("--motivo", default="")
    x = s.add_parser("anotar", help="registra una nota")
    x.add_argument("texto")
    s.add_parser("log", help="lista los asientos")
    s.add_parser("verificar", help="comprueba la integridad de la cadena")
    s.add_parser("vigencia", help="detecta afirmaciones cuya evidencia cambió")
    x = s.add_parser("reejecutar", help="repite el comando de una afirmación")
    x.add_argument("ref")
    x = s.add_parser("sello", help="emite o comprueba un sello del estado")
    x.add_argument("--comprobar", metavar="ARCHIVO")
    x = s.add_parser("probar", help="prueba de inclusión de un asiento")
    x.add_argument("ref")
    x = s.add_parser("extiende", help="prueba de consistencia respecto al tamaño M")
    x.add_argument("m", type=int)
    x = s.add_parser("comprobar", help="verifica una prueba sin tener el libro")
    x.add_argument("archivo")

    argv = list(sys.argv[1:] if argv is None else argv)
    corte = argv.index("--") if "--" in argv else len(argv)
    argv, cmd = argv[:corte], argv[corte + 1:]
    a = p.parse_args(argv)
    if cmd and a.orden != "afirmar":
        p.error("`--` solo se admite en `afirmar`")
    clave = os.environ.get("LACRE_CLAVE")
    libro = Libro(a.libro, clave=clave.encode() if clave else None)

    try:
        if a.orden == "sellar":
            for f in a.archivos:
                print(_resumen(libro.sellar(f)))
        elif a.orden == "afirmar":
            print(_resumen(libro.afirmar(a.texto, _valor(a.valor), a.dep, cmd or None)))
        elif a.orden == "relevar":
            print(_resumen(libro.relevar(a.ref, a.por, a.motivo)))
        elif a.orden == "anotar":
            print(_resumen(libro.anotar(a.texto)))
        elif a.orden == "log":
            for e in libro:
                print(_resumen(e))
        elif a.orden == "verificar":
            print(f"íntegro: {libro.verificar()} asientos")
        elif a.orden == "vigencia":
            est = libro.vigencia()
            malos = 0
            for e in libro:
                if e["tipo"] not in ("nota", "relevo"):
                    malos += est[e["id"]] not in (VIGENTE, RELEVADA)
                    print(f"{est[e['id']]:<9}{_resumen(e)}")
            return 1 if malos else 0
        elif a.orden == "reejecutar":
            ok = libro.reejecutar(a.ref)
            print("reproducida" if ok else "diverge")
            return 0 if ok else 1
        elif a.orden == "sello":
            if a.comprobar:
                with open(a.comprobar, encoding="utf-8") as f:
                    ok = libro.verificar_sello(json.load(f))
                print("sello válido" if ok else "SELLO NO VÁLIDO")
                return 0 if ok else 1
            _json(libro.sello())
        elif a.orden == "probar":
            _json(libro.probar(a.ref))
        elif a.orden == "extiende":
            _json(libro.extiende(a.m))
        elif a.orden == "comprobar":
            with open(a.archivo, encoding="utf-8") as f:
                ok = comprobar(json.load(f))
            print("prueba válida" if ok else "PRUEBA NO VÁLIDA")
            return 0 if ok else 1
    except (LacreError, OSError, ValueError) as e:
        print(f"lacre: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
