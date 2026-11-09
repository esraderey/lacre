import hashlib
import json
import sys
import threading

import pytest

import lacre
from lacre import (CADUCA, HUERFANA, VIGENTE, LacreError, Libro, LibroCorrupto,
                   comprobar, raiz_merkle, verificar_consistencia, verificar_inclusion)
from lacre import _camino, _sub
from lacre.__main__ import main

N = 40
HOJAS = [hashlib.sha256(b"\x00" + bytes([i])).digest() for i in range(N)]


# ── Merkle ────────────────────────────────────────────────────────────────────

def test_vectores_rfc6962():
    # Vectores de referencia de Certificate Transparency.
    datos = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
             b"\x50\x51\x52\x53\x54\x55\x56\x57",
             b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"]
    hs = [hashlib.sha256(b"\x00" + d).digest() for d in datos]
    assert raiz_merkle([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert raiz_merkle(hs[:1]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert raiz_merkle(hs[:3]).hex() == "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"
    assert raiz_merkle(hs).hex() == "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"


def test_inclusion_exhaustiva():
    for n in range(1, N + 1):
        r = raiz_merkle(HOJAS[:n])
        for i in range(n):
            c = _camino(i, HOJAS, 0, n)
            assert verificar_inclusion(i, n, HOJAS[i], c, r)
            assert not verificar_inclusion(i, n, HOJAS[(i + 1) % N], c, r)
            assert not verificar_inclusion(i, n, HOJAS[i], c + [HOJAS[0]], r)
            if c:
                assert not verificar_inclusion(i, n, HOJAS[i], c[:-1], r)
                assert not verificar_inclusion((i + 1) % n, n, HOJAS[i], c, r) or n == 1


def test_consistencia_exhaustiva():
    for n in range(1, N + 1):
        rn = raiz_merkle(HOJAS[:n])
        for m in range(1, n):
            rm = raiz_merkle(HOJAS[:m])
            c = _sub(m, HOJAS, 0, n, True)
            assert verificar_consistencia(m, n, c, rm, rn)
            assert not verificar_consistencia(m, n, c, rn, rn)
            assert not verificar_consistencia(m, n, c, rm, rm)
            assert not verificar_consistencia(m, n, c[:-1], rm, rn)
            malo = [bytes(32)] + c[1:]
            assert not verificar_consistencia(m, n, malo, rm, rn) or (m & (m - 1) == 0 and len(c) == 0)
        assert verificar_consistencia(n, n, [], rn, rn)
        assert verificar_consistencia(0, n, [], raiz_merkle([]), rn)


def test_consistencia_detecta_historia_reescrita():
    otras = list(HOJAS)
    otras[3] = bytes(32)
    c = _sub(8, otras, 0, 20, True)
    assert not verificar_consistencia(8, 20, c, raiz_merkle(HOJAS[:8]), raiz_merkle(otras[:20]))


# ── libro ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def libro(tmp_path):
    t = iter(range(1000, 10**6))
    return Libro(tmp_path / "lacre.jsonl", reloj=lambda: next(t))


def _lineas(libro):
    return libro.ruta.read_bytes().splitlines(keepends=True)


def test_cadena_y_determinismo(libro, tmp_path):
    assert libro.verificar() == 0
    a = libro.anotar("uno")
    b = libro.anotar("dos")
    assert (a["n"], b["n"], b["prev"]) == (0, 1, a["id"])
    assert libro.verificar() == 2
    t = iter(range(1000, 10**6))
    gemelo = Libro(tmp_path / "g" / "lacre.jsonl", reloj=lambda: next(t))
    gemelo.anotar("uno")
    gemelo.anotar("dos")
    assert gemelo.sello()["raiz"] == libro.sello()["raiz"]


@pytest.mark.parametrize("ataque", ["editar", "borrar", "reordenar", "truncar_linea", "basura"])
def test_manipulacion_detectada(libro, ataque):
    for i in range(5):
        libro.anotar(f"nota {i}")
    ls = _lineas(libro)
    if ataque == "editar":
        ls[2] = ls[2].replace(b"nota 2", b"nota X")
    elif ataque == "borrar":
        del ls[2]
    elif ataque == "reordenar":
        ls[1], ls[2] = ls[2], ls[1]
    elif ataque == "truncar_linea":
        ls[-1] = ls[-1][:-5]
    else:
        ls.append(b"{no json\n")
    libro.ruta.write_bytes(b"".join(ls))
    with pytest.raises(LibroCorrupto):
        libro.verificar()
    with pytest.raises(LibroCorrupto):
        libro.anotar("no debe anexar sobre un libro corrupto")


def test_edicion_con_id_recalculado_rompe_la_cadena(libro):
    for i in range(3):
        libro.anotar(f"nota {i}")
    ls = _lineas(libro)
    a = json.loads(ls[1])
    a["c"]["texto"] = "falsa"
    a["id"] = lacre._id(a)
    ls[1] = lacre._canon(a) + b"\n"
    libro.ruta.write_bytes(b"".join(ls))
    with pytest.raises(LibroCorrupto, match="asiento 2"):
        libro.verificar()


def test_sello_detecta_truncado_y_reescritura(libro):
    for i in range(6):
        libro.anotar(f"nota {i}")
    s = libro.sello()
    libro.anotar("posterior")
    assert libro.verificar_sello(s)                      # crecer no invalida
    ls = _lineas(libro)
    libro.ruta.write_bytes(b"".join(ls[:4]))             # prefijo válido, pero más corto
    assert libro.verificar() == 4
    assert not libro.verificar_sello(s)
    libro.ruta.unlink()                                  # historia alternativa íntegra
    for i in range(7):
        libro.anotar(f"otra {i}")
    assert not libro.verificar_sello(s)


def test_sello_firmado(tmp_path):
    a = Libro(tmp_path / "l.jsonl", clave=b"secreto")
    a.anotar("x")
    s = a.sello()
    assert a.verificar_sello(s)
    assert not Libro(a.ruta, clave=b"otra").verificar_sello(s)
    assert not a.verificar_sello({**s, "t": s["t"] + 1})
    with pytest.raises(LacreError):
        Libro(a.ruta)._mac(s)


def test_vigencia_se_propaga(libro, tmp_path):
    datos = tmp_path / "datos.csv"
    modelo = tmp_path / "modelo.bin"
    datos.write_text("a,b\n1,2\n")
    modelo.write_bytes(b"\x01\x02")
    d, m = libro.sellar(datos), libro.sellar(modelo)
    assert d["c"]["ruta"] == "datos.csv"
    base = libro.afirmar("accuracy", 0.93, deps=[d["id"][:10], m["id"]])
    deriv = libro.afirmar("supera al baseline", deps=[base["id"]])
    suelta = libro.afirmar("sin dependencias")
    est = libro.vigencia()
    assert {est[x["id"]] for x in (d, m, base, deriv, suelta)} == {VIGENTE}

    datos.write_text("a,b\n1,3\n")
    est = libro.vigencia()
    assert (est[d["id"]], est[m["id"]]) == (CADUCA, VIGENTE)
    assert est[base["id"]] == est[deriv["id"]] == CADUCA
    assert est[suelta["id"]] == VIGENTE

    modelo.unlink()
    est = libro.vigencia()
    assert est[m["id"]] == est[base["id"]] == est[deriv["id"]] == HUERFANA

    datos.write_text("a,b\n1,2\n")                        # restaurar el contenido revalida
    modelo.write_bytes(b"\x01\x02")
    assert set(libro.vigencia().values()) == {VIGENTE}


def test_resellar_y_reafirmar(libro, tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("v1")
    a1 = libro.sellar(f)
    c1 = libro.afirmar("vieja", deps=[a1["id"]])
    f.write_text("v2")
    a2 = libro.sellar(f)
    c2 = libro.afirmar("nueva", deps=[a2["id"]])
    est = libro.vigencia()
    assert (est[c1["id"]], est[c2["id"]]) == (CADUCA, VIGENTE)


def test_referencias(libro, tmp_path):
    a = libro.anotar("x")
    with pytest.raises(LacreError, match="corta"):
        libro.buscar(a["id"][:7])
    with pytest.raises(LacreError, match="desconocida"):
        libro.afirmar("y", deps=["f" * 16])
    assert libro.verificar() == 1                        # la afirmación fallida no se anexó
    with pytest.raises(LacreError):
        libro.sellar(tmp_path / "no-existe")
    with pytest.raises(LacreError):
        libro.sellar(tmp_path)


def test_comando_como_evidencia(libro, tmp_path):
    ok = libro.afirmar("suma", 4, cmd=[sys.executable, "-c", "print(2+2)"])
    assert ok["c"]["cmd"]["rc"] == 0
    assert ok["c"]["cmd"]["salida"] == hashlib.sha256(b"4\n").hexdigest()
    assert libro.reejecutar(ok["id"][:12])

    (tmp_path / "n.txt").write_text("1")
    var = libro.afirmar("lee archivo", cmd=[sys.executable, "-c", "print(open('n.txt').read())"])
    assert libro.reejecutar(var["id"])
    (tmp_path / "n.txt").write_text("2")
    assert not libro.reejecutar(var["id"])

    falla = libro.afirmar("rc", cmd=[sys.executable, "-c", "raise SystemExit(3)"])
    assert falla["c"]["cmd"]["rc"] == 3
    with pytest.raises(LacreError):
        libro.afirmar("x", cmd=["comando-que-no-existe-xyz"])
    with pytest.raises(LacreError):
        libro.reejecutar(libro.anotar("sin cmd")["id"])


def test_pruebas_autocontenidas(libro):
    ids = [libro.anotar(f"n{i}")["id"] for i in range(11)]
    s5 = None
    for i, x in enumerate(ids):
        p = libro.probar(x[:10])
        assert p["i"] == i and comprobar(p)
        assert not comprobar({**p, "id": ids[(i + 1) % 11]})
        assert not comprobar({**p, "raiz": "00" * 32})
    for m in range(12):
        c = libro.extiende(m)
        assert comprobar(c)
        if m == 5:
            s5 = c["raiz_m"]
    assert s5 == raiz_merkle([bytes.fromhex(x) for x in ids[:5]]).hex()
    with pytest.raises(LacreError):
        libro.extiende(12)
    assert not comprobar({}) and not comprobar({"tipo": "inclusion", "camino": ["zz"]})


def test_escritores_concurrentes(tmp_path):
    ruta = tmp_path / "l.jsonl"
    errores = []

    def obrero(k):
        try:
            for i in range(20):
                Libro(ruta).anotar(f"{k}-{i}")
        except Exception as e:  # noqa: BLE001
            errores.append(e)

    hilos = [threading.Thread(target=obrero, args=(k,)) for k in range(4)]
    [h.start() for h in hilos]
    [h.join() for h in hilos]
    assert not errores
    assert Libro(ruta).verificar() == 80
    assert not ruta.with_name("l.jsonl.lock").exists()


def test_cerrojo_ocupado(libro):
    libro.ruta.with_name("lacre.jsonl.lock").write_text("")
    with pytest.raises(LacreError, match="cerrojo"), libro._cerrojo(espera=0.05):
        pass


# ── CLI ───────────────────────────────────────────────────────────────────────

def test_cli_flujo_completo(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LACRE_CLAVE", raising=False)
    monkeypatch.delenv("LACRE_LIBRO", raising=False)
    (tmp_path / "pesos.bin").write_bytes(b"abc")
    assert main(["sellar", "pesos.bin"]) == 0
    ref = capsys.readouterr().out.split()[1]
    assert main(["afirmar", "loss final", "--valor", "0.12", "--dep", ref,
                 "--", sys.executable, "-c", "print('ok')"]) == 0
    afirm = capsys.readouterr().out.split()[1]
    assert main(["anotar", "fin de corrida"]) == 0
    assert main(["verificar"]) == 0 and "3 asientos" in capsys.readouterr().out
    assert main(["log"]) == 0 and "= 0.12" in capsys.readouterr().out
    assert main(["vigencia"]) == 0
    assert main(["reejecutar", afirm]) == 0
    capsys.readouterr()

    assert main(["sello"]) == 0
    (tmp_path / "s.json").write_text(capsys.readouterr().out)
    assert main(["probar", afirm]) == 0
    (tmp_path / "p.json").write_text(capsys.readouterr().out)
    assert main(["extiende", "1"]) == 0
    (tmp_path / "c.json").write_text(capsys.readouterr().out)
    assert main(["sello", "--comprobar", "s.json"]) == 0
    assert main(["comprobar", "p.json"]) == 0
    assert main(["comprobar", "c.json"]) == 0

    (tmp_path / "pesos.bin").write_bytes(b"abd")
    assert main(["vigencia"]) == 1
    assert capsys.readouterr().out.count("caduca") == 2

    p = json.loads((tmp_path / "p.json").read_text())
    p["asiento"]["c"]["valor"] = 0.01
    p["id"] = lacre._id(p["asiento"])
    (tmp_path / "p.json").write_text(json.dumps(p))
    assert main(["comprobar", "p.json"]) == 1

    assert main(["probar", "ffffffff"]) == 2
    libro = tmp_path / "lacre.jsonl"
    libro.write_bytes(libro.read_bytes().replace(b"fin de corrida", b"fin de carrera"))
    assert main(["verificar"]) == 2
    assert main(["sello", "--comprobar", "s.json"]) == 1


# ── anclas de mutación ────────────────────────────────────────────────────────

def test_id_es_hoja_con_separacion_de_dominio(libro):
    a = libro.anotar("x")
    cuerpo = {k: a[k] for k in ("n", "t", "tipo", "c", "prev")}
    plano = json.dumps(cuerpo, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert a["id"] == hashlib.sha256(b"\x00" + plano).hexdigest()
    assert a["prev"] == "0" * 64


def test_sello_con_tamano_fuera_de_rango(libro):
    ids = [bytes.fromhex(libro.anotar(f"n{i}")["id"]) for i in range(4)]
    assert not libro.verificar_sello({"n": -1, "raiz": raiz_merkle(ids[:-1]).hex(), "t": 0})
    assert not libro.verificar_sello({"n": 9, "raiz": raiz_merkle(ids).hex(), "t": 0})
    assert not libro.verificar_sello({"raiz": "00"})
