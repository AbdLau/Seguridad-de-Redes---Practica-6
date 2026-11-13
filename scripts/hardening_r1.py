#!/usr/bin/env python3
"""
Script de Auditoría y Hardening Automatizado CIS Benchmark - Cisco IOS Router (R1)
Entorno: GNS3 Lab | Objetivo: 10.8.46.129
"""

import paramiko
import time
import re
from datetime import datetime

# ================= PARÁMETROS DE CONEXIÓN =================
HOST = "10.8.46.129"
USUARIO = "admin"
CLAVE = "cisco"          # Reemplazar según configuración local
ENABLE_PASS = "cisco"    # Contraseña de modo privilegiado (si aplica)
REPORTE_INICIAL = "informe_r1_inicial.txt"
REPORTE_POSTUMO = "informe_r1_postum.txt"
# ==========================================================

REGLAS_CIS_ROUTER = [
    {
        "id": "CIS-1.1",
        "titulo": "Servicio de cifrado de contraseñas activado",
        "comando_esperado": "service password-encryption",
        "patron": r"^service password-encryption",
        "severidad": "MEDIA",
    },
    {
        "id": "CIS-2.1",
        "titulo": "Keepalives TCP de entrada habilitados",
        "comando_esperado": "service tcp-keepalives-in",
        "patron": r"^service tcp-keepalives-in",
        "severidad": "BAJA",
    },
    {
        "id": "CIS-2.2",
        "titulo": "Keepalives TCP de salida habilitados",
        "comando_esperado": "service tcp-keepalives-out",
        "patron": r"^service tcp-keepalives-out",
        "severidad": "BAJA",
    },
    {
        "id": "CIS-3.1",
        "titulo": "Deshabilitar encamiamiento de origen (IP Source Routing)",
        "comando_esperado": "no ip source-route",
        "patron": r"^no ip source-route",
        "severidad": "ALTA",
    },
    {
        "id": "CIS-3.2",
        "titulo": "Deshabilitar servidor HTTP no seguro",
        "comando_esperado": "no ip http server",
        "patron": r"^no ip http server",
        "severidad": "MEDIA",
    },
    {
        "id": "CIS-4.1",
        "titulo": "Tiempo de espera de sesión SSH configurado (<= 60 seg)",
        "comando_esperado": "ip ssh time-out 60",
        "patron": r"^ip ssh time-out ([1-5]?[0-9]|60)\b",
        "severidad": "MEDIA",
    },
    {
        "id": "CIS-4.2",
        "titulo": "Intentos máximos de autenticación SSH (<= 3)",
        "comando_esperado": "ip ssh authentication-retries 3",
        "patron": r"^ip ssh authentication-retries [1-3]\b",
        "severidad": "MEDIA",
    },
    {
        "id": "CIS-6.1",
        "titulo": "Restricción exclusiva de transporte SSH en líneas VTY",
        "comando_esperado": "transport input ssh",
        "patron": r"^\s*transport input ssh\s*$",
        "severidad": "ALTA",
    },
    {
        "id": "CIS-6.2",
        "titulo": "Timeout de inactividad configurado en líneas VTY (<= 10 min)",
        "comando_esperado": "exec-timeout 10 0",
        "patron": r"^\s*exec-timeout ([1-9]|10) 0",
        "severidad": "MEDIA",
    },
]

def obtener_running_config(shell):
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    while shell.recv_ready():
        shell.recv(65535)

    shell.send("show running-config\n")
    time.sleep(2.5)

    salida = ""
    while shell.recv_ready():
        salida += shell.recv(65535).decode("utf-8", errors="ignore")
        time.sleep(0.3)
    return salida

def evaluar_configuracion(running_config, reglas):
    resultados = []
    cumplidos = 0

    for regla in reglas:
        match = re.search(regla["patron"], running_config, re.MULTILINE)
        estado = "CUMPLE" if match else "NO CUMPLE"
        if match:
            cumplidos += 1

        resultados.append({
            "id": regla["id"],
            "severidad": regla["severidad"],
            "estado": estado,
            "titulo": regla["titulo"],
            "esperado": regla["comando_esperado"],
        })

    total = len(reglas)
    porcentaje = (cumplidos / total) * 100
    return resultados, cumplidos, total, porcentaje

def generar_informe(resultados, cumplidos, total, porcentaje, fase):
    lineas = [
        "=" * 80,
        f"     INFORME DE AUDITORÍA CIS BENCHMARK - ROUTER R1 ({fase})",
        "=" * 80,
        f"Dispositivo Objetivo : {HOST}",
        f"Fecha de Auditoría   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Puntuación Obtenida  : {cumplidos}/{total} ({porcentaje:.1f}%)",
        "-" * 80,
        f"{'ID':<10} | {'SEVERIDAD':<10} | {'ESTADO':<10} | {'CONTROL EVALUADO'}",
        "-" * 80,
    ]
    for r in resultados:
        lineas.append(f"{r['id']:<10} | {r['severidad']:<10} | {r['estado']:<10} | {r['titulo']}")
        if r["estado"] == "NO CUMPLE":
            lineas.append(f"  └─ Remedio recomendado: {r['esperado']}")
    lineas.append("=" * 80)
    return "\n".join(lineas)

def main():
    print(f"[*] Conectando al Router R1 ({HOST}) vía SSH...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname=HOST, username=USUARIO, password=CLAVE, look_for_keys=False, allow_agent=False, timeout=15)
    except Exception as e:
        print(f"[-] Error de conexión: {e}")
        return

    shell = client.invoke_shell()
    time.sleep(1.5)
    shell.send("enable\n")
    time.sleep(0.5)
    shell.send(f"{ENABLE_PASS}\n")
    time.sleep(0.5)

    print("[*] Extrayendo running-config para auditoría inicial...")
    config_ini = obtener_running_config(shell)
    res_ini, c_ini, t_ini, p_ini = evaluar_configuracion(config_ini, REGLAS_CIS_ROUTER)
    texto_ini = generar_informe(res_ini, c_ini, t_ini, p_ini, "INICIAL")

    print("\n" + texto_ini + "\n")
    with open(REPORTE_INICIAL, "w", encoding="utf-8") as f:
        f.write(texto_ini)
    print(f"[+] Informe inicial guardado en {REPORTE_INICIAL}")

    opcion = input("\n[?] ¿Desea aplicar automáticamente las remediaciones CIS en R1? (s/n): ").strip().lower()
    if opcion in ["s", "si", "sí", "y", "yes"]:
        print("[*] Aplicando controles CIS Benchmark en R1...")
        comandos_hardening = [
            "configure terminal",
            "service password-encryption",
            "service tcp-keepalives-in",
            "service tcp-keepalives-out",
            "no ip source-route",
            "no ip http server",
            "no ip bootp server",
            "no cdp run",
            "ip ssh time-out 60",
            "ip ssh authentication-retries 3",
            "line vty 0 4",
            "transport input ssh",
            "exec-timeout 10 0",
            "exit",
            "line con 0",
            "exec-timeout 10 0",
            "exit",
            "end",
            "write memory",
        ]
        for cmd in comandos_hardening:
            shell.send(cmd + "\n")
            time.sleep(0.4)

        time.sleep(2)
        print("[+] Remediación aplicada y guardada en NVRAM. Verificando estado póstumo...")
        config_post = obtener_running_config(shell)
        res_post, c_post, t_post, p_post = evaluar_configuracion(config_post, REGLAS_CIS_ROUTER)
        texto_post = generar_informe(res_post, c_post, t_post, p_post, "PÓSTUMO (TRAS REMEDIACIÓN)")

        print("\n" + texto_post + "\n")
        with open(REPORTE_POSTUMO, "w", encoding="utf-8") as f:
            f.write(texto_post)
        print(f"[+] Informe póstumo guardado en {REPORTE_POSTUMO}")
    else:
        print("[-] Operación cancelada. No se realizaron modificaciones.")

    client.close()
    print("[*] Sesión SSH finalizada.")

if __name__ == "__main__":
    main()
