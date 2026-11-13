#!/usr/bin/env python3

import paramiko
import time
import re
from datetime import datetime

# ================= PARÁMETROS DE CONEXIÓN =================
HOST = "10.8.46.200"
USUARIO = "admin"
CLAVE = "cisco"          # Reemplazar según configuración local
ENABLE_PASS = "cisco"    # Contraseña de modo privilegiado (si aplica)
ARCHIVO_SALIDA = "informe_cis_inicial.txt"
# ==========================================================

REGLAS_CIS_SWITCH = [
    {
        "id": "CIS-1.1",
        "titulo": "Servicio de cifrado de contraseñas activado",
        "comando_esperado": "service password-encryption",
        "patron": r"^service password-encryption",
        "severidad": "MEDIA",
    },
    {
        "id": "CIS-3.2",
        "titulo": "Deshabilitar servidor HTTP no seguro",
        "comando_esperado": "no ip http server",
        "patron": r"^no ip http server",
        "severidad": "MEDIA",
    },
    {
        "id": "CIS-6.1",
        "titulo": "Restricción de transporte SSH en líneas VTY",
        "comando_esperado": "transport input ssh",
        "patron": r"^\s*transport input ssh\s*$",
        "severidad": "ALTA",
    },
    {
        "id": "CIS-6.2",
        "titulo": "Timeout de inactividad configurado en líneas VTY",
        "comando_esperado": "exec-timeout 10 0",
        "patron": r"^\s*exec-timeout ([1-9]|10) 0",
        "severidad": "MEDIA",
    },
]

def auditar_switch():
    print(f"[*] Conectando al Switch SW1 ({HOST}) vía SSH...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(hostname=HOST, username=USUARIO, password=CLAVE, look_for_keys=False, allow_agent=False, timeout=15)
    except Exception as e:
        print(f"[-] Error de conexión con el Switch: {e}")
        return

    shell = client.invoke_shell()
    time.sleep(1.5)
    shell.send("enable\n")
    time.sleep(0.5)
    shell.send(f"{ENABLE_PASS}\n")
    time.sleep(0.5)
    shell.send("terminal length 0\n")
    time.sleep(0.5)

    while shell.recv_ready():
        shell.recv(65535)

    shell.send("show running-config\n")
    time.sleep(2.5)

    running_config = ""
    while shell.recv_ready():
        running_config += shell.recv(65535).decode("utf-8", errors="ignore")
        time.sleep(0.3)

    cumplidos = 0
    resultados = []

    for r in REGLAS_CIS_SWITCH:
        match = re.search(r["patron"], running_config, re.MULTILINE)
        estado = "CUMPLE" if match else "NO CUMPLE"
        if match:
            cumplidos += 1
        resultados.append({**r, "estado": estado})

    total = len(REGLAS_CIS_SWITCH)
    porcentaje = (cumplidos / total) * 100

    lineas = [
        "=" * 80,
        "        INFORME DE AUDITORÍA DE HARDENING CIS - CISCO IOS (SW1)",
        "=" * 80,
        f"Dispositivo Objetivo : {HOST}",
        f"Fecha de Auditoría   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Modo de Operación    : ANÁLISIS DIRECTO POR SSH (Sin aplicar cambios)",
        f"Puntuación Obtenida  : {cumplidos}/{total} ({porcentaje:.1f}%)",
        "-" * 80,
        f"{'ID':<10} | {'SEVERIDAD':<10} | {'ESTADO':<10} | {'CONTROL EVALUADO'}",
        "-" * 80,
    ]

    for item in resultados:
        lineas.append(f"{item['id']:<10} | {item['severidad']:<10} | {item['estado']:<10} | {item['titulo']}")
        if item["estado"] == "NO CUMPLE":
            lineas.append(f"  └─ Remedio recomendado: {item['comando_esperado']}")

    lineas.append("=" * 80)
    reporte_final = "\n".join(lineas)

    print("\n" + reporte_final + "\n")
    with open(ARCHIVO_SALIDA, "w", encoding="utf-8") as f:
        f.write(reporte_final)
    print(f"[+] Informe guardado exitosamente en {ARCHIVO_SALIDA}")

    client.close()

if __name__ == "__main__":
    auditar_switch()
