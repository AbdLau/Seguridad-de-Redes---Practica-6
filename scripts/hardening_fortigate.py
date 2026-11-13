#!/usr/bin/env python3

import paramiko
import time
import re
from datetime import datetime

# ---------- CONFIGURACIÓN DE TU FORTIGATE ----------
HOST = "10.8.46.99"          # IP de gestión en port3
USUARIO = "admin"            # Usuario administrador
CLAVE = ""                   # Contraseña del FortiGate
REPORTE_INICIAL = "informe_fortigate_inicial.txt"
REPORTE_POSTUMO = "informe_fortigate_postum.txt"
# ---------------------------------------------------

def evaluar_configuracion_fortigate(output_text):
    reglas = [
        {
            "id": "FORTI-1.1",
            "titulo": "Inactividad de consola (Idle-timeout <= 15 min)",
            "comando_esperado": "set admintimeout 10",
            "patron": r"set admintimeout ([1-9]|1[0-5])\b",
            "severidad": "MEDIA",
        },
        {
            "id": "FORTI-2.1",
            "titulo": "Banner de advertencia Pre-Login habilitado",
            "comando_esperado": "set pre-login-banner enable",
            "patron": r"set pre-login-banner enable",
            "severidad": "BAJA",
        },
        {
            "id": "FORTI-3.1",
            "titulo": "Transferencia segura SCP para respaldos activa",
            "comando_esperado": "set admin-scp enable",
            "patron": r"set admin-scp enable",
            "severidad": "MEDIA",
        },
    ]

    resultados = []
    puntos_cumplidos = 0

    for r in reglas:
        match = re.search(r["patron"], output_text, re.MULTILINE | re.IGNORECASE)
        cumple = bool(match)

        if cumple:
            puntos_cumplidos += 1
            estado = "CUMPLE"
        else:
            estado = "NO CUMPLE"

        resultados.append({
            "id": r["id"],
            "titulo": r["titulo"],
            "severidad": r["severidad"],
            "esperado": r["comando_esperado"],
            "estado": estado,
        })

    total = len(reglas)
    porcentaje = (puntos_cumplidos / total) * 100
    return resultados, puntos_cumplidos, total, porcentaje

def generar_texto_informe(resultados, puntos, total, porcentaje, tipo_informe):
    lineas = [
        "=" * 80,
        f"     INFORME DE HARDENING - FORTIGATE FIREWALL ({tipo_informe})",
        "=" * 80,
        f"Dispositivo Objetivo : {HOST}",
        f"Fecha de Auditoría   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Puntuación Obtenida  : {puntos}/{total} ({porcentaje:.1f}%)",
        "-" * 80,
        f"{'ID':<10} | {'SEVERIDAD':<10} | {'ESTADO':<10} | {'CONTROL EVALUADO'}",
        "-" * 80,
    ]

    for item in resultados:
        lineas.append(
            f"{item['id']:<10} | {item['severidad']:<10} | {item['estado']:<10} | {item['titulo']}"
        )
        if item["estado"] == "NO CUMPLE":
            lineas.append(f"  └─ Remedio recomendado: {item['esperado']}")

    lineas.append("=" * 80)
    return "\n".join(lineas)

def main():
    print(f"[*] Conectando al Firewall FortiGate ({HOST}) vía SSH...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=HOST,
            username=USUARIO,
            password=CLAVE,
            look_for_keys=False,
            allow_agent=False,
            timeout=15
        )
    except Exception as e:
        print(f"[-] Error de conexión con el FortiGate: {e}")
        return

    print("[+] Conectado al FortiGate. Abriendo shell interactivo...")
    shell = client.invoke_shell()
    time.sleep(2)

    while shell.recv_ready():
        shell.recv(65535)
        time.sleep(0.2)

    # 1. Obtener la configuración inicial
    print("[*] Obteniendo configuración inicial del Firewall...")
    shell.send("show system global\n")
    time.sleep(2)

    output_inicial = ""
    while shell.recv_ready():
        output_inicial += shell.recv(65535).decode("utf-8", errors="ignore")
        time.sleep(0.3)

    res_ini, p_ini, tot_ini, por_ini = evaluar_configuracion_fortigate(output_inicial)
    inf_inicial = generar_texto_informe(res_ini, p_ini, tot_ini, por_ini, "INICIAL")
    
    print("\n" + inf_inicial + "\n")
    with open(REPORTE_INICIAL, "w", encoding="utf-8") as f:
        f.write(inf_inicial)
    print(f"[+] Informe inicial del Firewall guardado en {REPORTE_INICIAL}")

    # 2. Preguntar interactivamente si se desea aplicar el Hardening
    print("\n" + "="*80)
    opcion = input("[?] ¿Desea aplicar las recomendaciones CIS en el FortiGate? (s/n): ").strip().lower()
    print("="*80)

    if opcion in ['s', 'si', 'sí', 'y', 'yes']:
        print("\n[*] Aplicando reglas de hardening en el FortiGate...")
        comandos_remediacion = [
            "config system global",
            "set admintimeout 10",
            "set pre-login-banner enable",
            "set admin-scp enable",
            "end"
        ]
        
        for cmd in comandos_remediacion:
            shell.send(cmd + "\n")
            time.sleep(0.5)

        # Limpiar buffer de comandos aplicados
        time.sleep(1)
        while shell.recv_ready():
            shell.recv(65535)
            time.sleep(0.2)

        print("[+] Directivas de hardening aplicadas en el Firewall con éxito.")

        # 3. Obtener configuración póstuma real
        print("[*] Verificando estado póstumo del Firewall...")
        shell.send("show system global\n")
        time.sleep(2)

        output_post = ""
        while shell.recv_ready():
            output_post += shell.recv(65535).decode("utf-8", errors="ignore")
            time.sleep(0.3)

        res_post, p_post, tot_post, por_post = evaluar_configuracion_fortigate(output_post)
        inf_postumo = generar_texto_informe(res_post, p_post, tot_post, por_post, "PÓSTUMO (TRAS REMEDIACIÓN)")

        print("\n" + inf_postumo + "\n")
        with open(REPORTE_POSTUMO, "w", encoding="utf-8") as f:
            f.write(inf_postumo)
        print(f"[+] Informe póstumo del Firewall guardado exitosamente en {REPORTE_POSTUMO}")
    else:
        print("\n[-] Operación cancelada. No se aplicaron cambios en el Firewall.")

    client.close()
    print("[*] Conexión cerrada con el FortiGate.")

if __name__ == "__main__":
    main()
