"""Detector de forca bruta em logs de autenticacao SSH.

Mapeamento MITRE ATT&CK:
  T1110.001 - Brute Force: Password Guessing
  T1110.003 - Brute Force: Password Spraying
"""
import re
import sys
from collections import defaultdict
from datetime import datetime

LIMITE_FALHAS = 4        # falhas dentro da janela para considerar forca bruta
JANELA_SEGUNDOS = 60     # tamanho da janela de tempo
LIMITE_USUARIOS = 3      # usuarios distintos tentados pelo mesmo IP (spraying)
ANO = datetime.now().year  # logs syslog nao trazem o ano

PADRAO = re.compile(
    r"^(?P<data>\w{3}\s+\d+\s+[\d:]{8}).*?"
    r"(?P<res>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<usuario>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def converter_data(texto):
    texto = " ".join(texto.split())
    return datetime.strptime(f"{ANO} {texto}", "%Y %b %d %H:%M:%S")


def analisar_log(caminho):
    eventos = defaultdict(list)  # ip -> [(data, resultado, usuario)]
    with open(caminho, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            m = PADRAO.search(linha)
            if m:
                eventos[m["ip"]].append(
                    (converter_data(m["data"]), m["res"], m["usuario"])
                )
    return eventos


def maior_rajada(tempos, janela):
    """Maior numero de falhas dentro de qualquer janela deslizante."""
    tempos = sorted(tempos)
    melhor, inicio = 0, 0
    for fim in range(len(tempos)):
        while (tempos[fim] - tempos[inicio]).total_seconds() > janela:
            inicio += 1
        melhor = max(melhor, fim - inicio + 1)
    return melhor


def avaliar_ip(lista):
    falhas = [e for e in lista if e[1] == "Failed"]
    sucessos = [e for e in lista if e[1] == "Accepted"]
    rajada = maior_rajada([e[0] for e in falhas], JANELA_SEGUNDOS)
    usuarios = {e[2] for e in falhas}

    forca_bruta = rajada >= LIMITE_FALHAS
    spraying = len(usuarios) >= LIMITE_USUARIOS
    sucesso_apos_falhas = any(
        sum(1 for f in falhas if f[0] <= s[0]) >= LIMITE_FALHAS for s in sucessos
    )

    if (forca_bruta or spraying) and sucesso_apos_falhas:
        status = "CRITICO (login com sucesso apos ataque)"
    elif forca_bruta or spraying:
        status = "SUSPEITO"
    else:
        status = "ok"

    tecnicas = []
    if forca_bruta:
        tecnicas.append("T1110.001")
    if spraying:
        tecnicas.append("T1110.003")

    return {
        "falhas": len(falhas), "rajada": rajada, "usuarios": len(usuarios),
        "status": status, "tecnicas": tecnicas,
    }


def gerar_relatorio(eventos):
    print("=" * 60)
    print("RELATORIO DE TRIAGEM - TENTATIVAS DE LOGIN FALHAS")
    print(f"Regra: >= {LIMITE_FALHAS} falhas em {JANELA_SEGUNDOS}s "
          f"ou >= {LIMITE_USUARIOS} usuarios por IP")
    print("=" * 60)
    if not eventos:
        print("Nenhuma tentativa de login encontrada no log.")
        return

    resultados = {ip: avaliar_ip(lista) for ip, lista in eventos.items()}
    ordenados = sorted(resultados.items(), key=lambda i: i[1]["falhas"], reverse=True)
    for ip, r in ordenados:
        print(f"IP: {ip:<16} | Falhas: {r['falhas']:<3} | "
              f"Rajada: {r['rajada']:<3} | Usuarios: {r['usuarios']:<2} | "
              f"Status: {r['status']}")
        if r["tecnicas"]:
            print(f"    MITRE ATT&CK: {', '.join(r['tecnicas'])}")
    print("-" * 60)
    alvos = [ip for ip, r in resultados.items() if r["status"] != "ok"]
    print(f"Total de IPs suspeitos encontrados: {len(alvos)}")
    if alvos:
        print(f"IPs recomendados para bloqueio no firewall: {', '.join(alvos)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python detector_forca_bruta.py <caminho_do_log>")
        sys.exit(1)
    gerar_relatorio(analisar_log(sys.argv[1]))
