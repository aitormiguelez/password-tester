#!/usr/bin/env python3

import argparse
import sys
import json
from getpass import getpass

from password_analyzer import analizar_password
from hibp_api import check_pwned

log_path = "/Users/aitormiguelez/Documents/Projects/secmifor/.cursor/debug.log"
def _log(msg, data=None, hypothesis_id=None, location=None):
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps({"timestamp": __import__("time").time() * 1000, "sessionId": "debug-session", "runId": "run1", "hypothesisId": hypothesis_id or "D", "location": location or "password_tester.py", "message": msg, "data": data or {}}) + "\n")
    except: pass


def parse_args():
    parser = argparse.ArgumentParser(description="Pequeño tester de contraseñas en Python")
    parser.add_argument(
        "--password",
        help="Contraseña a evaluar (no recomendado, mejor dejar vacío y escribirla de forma oculta)."
    )
    parser.add_argument(
        "--no-hibp",
        action="store_true",
        help="No consultar Have I Been Pwned."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout para la consulta a HIBP (s)."
    )
    return parser.parse_args()


def main():
    _log("main ENTRY", {}, "D", "password_tester.py:31")
    args = parse_args()

    if args.password:
        pwd = args.password
        _log("Password from args", {"pwd_length": len(pwd)}, "D", "password_tester.py:35")
        print("[!] Aviso: has pasado la contraseña como argumento. "
              "Puede quedar guardada en el historial del terminal.")
    else:
        try:
            pwd = getpass("Introduce la contraseña a evaluar: ")
            _log("Password from getpass", {"pwd_length": len(pwd)}, "D", "password_tester.py:40")
        except KeyboardInterrupt:
            print("\nCancelado por el usuario.")
            sys.exit(0)
    _log("Before analizar_password call", {"pwd_length": len(pwd)}, "D", "password_tester.py:45")
    try:
        datos = analizar_password(pwd)
        _log("After analizar_password call", {"has_data": datos is not None}, "D", "password_tester.py:45")
    except Exception as e:
        _log("Exception in analizar_password", {"error": str(e), "error_type": type(e).__name__}, "D", "password_tester.py:45")
        raise

    print("\n=== Resultado del análisis ===")
    print("Longitud: %d" % datos["length"])
    print("Entropía aproximada: %s bits" % datos["entropy"])
    print("Puntuación: %d / 100" % datos["score"])
    print("Nivel: %s" % datos["level"])

    if datos["issues"]:
        print("\nProblemas detectados:")
        for i in datos["issues"]:
            print(" - %s" % i)
    else:
        print("\nNo he visto problemas claros en la estructura de la contraseña.")

    if datos["suggestions"]:
        print("\nSugerencias:")
        for s in datos["suggestions"]:
            print(" - %s" % s)

    if not args.no_hibp:
        print("\nComprobando si ha aparecido en filtraciones públicas (Have I Been Pwned)...")
        count = check_pwned(pwd, timeout=args.timeout)
        if count is None:
            print("No se ha podido consultar la API de HIBP (problema de red o límite).")
        elif count == 0:
            print("No aparece en la base de datos pública de contraseñas filtradas.")
        else:
            print("OJO: esta contraseña aparece %d veces en filtraciones públicas." % count)
            print("Mejor no usarla ni reutilizarla.")
    else:
        print("\nHas desactivado la consulta a HIBP (--no-hibp).")

    print("\nConsejo general: usa un gestor de contraseñas y no reutilices la misma en varios sitios.")


if __name__ == "__main__":
    main()