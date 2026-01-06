# Password Tester

Herramienta en Python para evaluar la fortaleza de una contraseña y comprobar si ha aparecido en filtraciones públicas (Have I Been Pwned).

## Características

- Análisis de:
  - longitud
  - tipos de caracteres (mayúsculas, minúsculas, números, símbolos)
  - patrones débiles y secuencias típicas
  - entropía aproximada
- Puntuación de 0 a 100 y nivel textual (Muy débil → Muy fuerte)
- Recomendaciones automáticas de mejora
- Comprobación opcional en la API de Pwned Passwords (HIBP) usando k-anonymity
- Interfaz de línea de comandos (CLI) sencilla

## Como usarla
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python password_tester.py
