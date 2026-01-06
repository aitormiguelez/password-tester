import math
import string
import json
import os

def calcular_entropia(password):
    """
    Calcula una entropía aproximada basándose en:
    - longitud
    - tipos de caracteres usados
    No es matemática perfecta, pero sirve como referencia.
    """
    if not password:
        return 0.0

    espacio = 0

    if any(c.islower() for c in password):
        espacio += 26
    if any(c.isupper() for c in password):
        espacio += 26
    if any(c.isdigit() for c in password):
        espacio += 10
    if any(c in string.punctuation for c in password):
        espacio += len(string.punctuation)

    if espacio == 0:
        return 0.0

    return len(password) * math.log2(espacio)


def buscar_patrones(password):
    """
    Busca patrones típicos que suelen aparecer
    en contraseñas débiles.
    """
    password = password.lower()
    resultados = []

    patrones_comunes = [
        "1234", "12345", "123456",
        "password", "admin", "qwerty",
        "abc123", "iloveyou",
        "0000", "1111"
    ]

    secuencias_teclado = [
        "qwerty", "asdf", "zxcv",
        "1q2w3e", "qaz", "qwe"
    ]

    for patron in patrones_comunes:
        if patron in password:
            resultados.append(f"Contiene patrón común: '{patron}'")

    for secuencia in secuencias_teclado:
        if secuencia in password:
            resultados.append(f"Secuencia de teclado típica: '{secuencia}'")

    return resultados


def analizar_password(password):
    """
    Analiza la contraseña y devuelve un diccionario
    con métricas y recomendaciones.
    """
    longitud = len(password)
    entropia = calcular_entropia(password)

    problemas = []
    sugerencias = []
    puntuacion = 0

    if longitud == 0:
        return {
            "length": 0,
            "entropy": 0.0,
            "score": 0,
            "level": "Vacía",
            "issues": ["La contraseña está vacía."],
            "suggestions": ["Introduce una contraseña para poder evaluarla."]
        }

    # Tipos de caracteres
    tiene_minusculas = any(c.islower() for c in password)
    tiene_mayusculas = any(c.isupper() for c in password)
    tiene_numeros = any(c.isdigit() for c in password)
    tiene_simbolos = any(c in string.punctuation for c in password)

    tipos_usados = sum([
        tiene_minusculas,
        tiene_mayusculas,
        tiene_numeros,
        tiene_simbolos
    ])

    # Longitud
    if longitud < 6:
        puntuacion += 5
        problemas.append("Contraseña demasiado corta.")
        sugerencias.append("Usa al menos 10–12 caracteres.")
    elif longitud < 10:
        puntuacion += 20
        sugerencias.append("Una longitud mayor mejoraría la seguridad.")
    elif longitud < 14:
        puntuacion += 40
    else:
        puntuacion += 55

    # Variedad de caracteres
    if tipos_usados == 1:
        puntuacion += 5
        problemas.append("Solo usa un tipo de carácter.")
        sugerencias.append("Mezcla mayúsculas, minúsculas, números y símbolos.")
    elif tipos_usados == 2:
        puntuacion += 15
        sugerencias.append("Añadir más tipos de caracteres aumentaría la seguridad.")
    elif tipos_usados == 3:
        puntuacion += 25
    elif tipos_usados == 4:
        puntuacion += 35

    # Repetición excesiva
    if len(set(password)) <= max(3, longitud // 2):
        problemas.append("Muchos caracteres repetidos.")
        sugerencias.append("Evita repetir demasiadas veces el mismo carácter.")
        puntuacion -= 10

    # Patrones conocidos
    patrones_detectados = buscar_patrones(password)
    if patrones_detectados:
        problemas.extend(patrones_detectados)
        puntuacion -= 20

    # Ajuste por entropía
    if entropia < 28:
        problemas.append("Entropía muy baja.")
        sugerencias.append("Haz la contraseña más larga y variada.")
        puntuacion -= 10
    elif entropia < 60:
        puntuacion += 10
    else:
        puntuacion += 15

    # Normalizar puntuación
    puntuacion = max(0, min(100, puntuacion))

    if puntuacion < 20:
        nivel = "Muy débil"
    elif puntuacion < 40:
        nivel = "Débil"
    elif puntuacion < 60:
        nivel = "Media"
    elif puntuacion < 80:
        nivel = "Fuerte"
    else:
        nivel = "Muy fuerte"

    return {
        "length": longitud,
        "entropy": round(entropia, 2),
        "score": puntuacion,
        "level": nivel,
        "issues": problemas,
        "suggestions": sugerencias,
    }