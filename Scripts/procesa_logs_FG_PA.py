import os
import re
import csv


def extraer_flujo(linea, engine):
    """Extrae la tupla (IP_Origen, IP_Destino, Puerto_Destino) según el firewall."""
    src, dst, pt = "Desconocido", "Desconocido", "Desconocido"

    if engine == 'FG':
        m_src = re.search(r'srcip=([^\s]+)', linea)
        m_dst = re.search(r'dstip=([^\s]+)', linea)
        m_pt = re.search(r'dstport=([^\s]+)', linea)
        if m_src: src = m_src.group(1).strip()
        if m_dst: dst = m_dst.group(1).strip()
        if m_pt: pt = m_pt.group(1).strip()

    elif engine == 'PA':
        m_src = re.search(r'src="?([^"\s,]+)"?', linea)
        m_dst = re.search(r'dst="?([^"\s,]+)"?', linea)
        m_pt = re.search(r'dport="?([^"\s,]+)"?', linea)
        if m_src: src = m_src.group(1).strip()
        if m_dst: dst = m_dst.group(1).strip()
        if m_pt: pt = m_pt.group(1).strip()

    return f"{src} -> {dst}:{pt}"


def procesar_trafico(engine, traffic_type):
    base_dir = os.path.join(engine, traffic_type)

    if not os.path.exists(base_dir):
        return

    print(f"[*] Procesando logs de {engine} - {traffic_type}...")

    out_dir = os.path.join(base_dir, "resultados_logs")
    os.makedirs(out_dir, exist_ok=True)

    # Estructuras de datos
    resumen_pcaps = {}
    stats_ips = {}
    stats_app = {}

    for filename in os.listdir(base_dir):
        if not (filename.endswith('.log') or filename.endswith('.txt')):
            continue

        pcap_name = os.path.splitext(filename)[0]
        ruta_archivo = os.path.join(base_dir, filename)

        resumen_pcaps[pcap_name] = {
            'alerts_global_or': 0,  # Alertas consolidadas (IPS || APP)
            'alerts_ips': 0, 'alerts_app': 0,
            'ips_ids': set(), 'app_ids': set(), 'flows': set()
        }

        try:
            with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ips_match, app_match = None, None

                    if engine == 'FG':
                        ips_match = re.search(r'attackid=(\d+)', line)
                        app_match = re.search(r'appid=(\d+)', line)
                    elif engine == 'PA':
                        ips_match = re.search(r'threatid="?([^"\s,]+)"?', line)
                        app_match = re.search(r'(?:appid|app)="?([^"\s,]+)"?', line)

                    # Si hay CUALQUIER tipo de alerta en la línea (IPS || APP), sumamos 1 alerta global
                    if ips_match or app_match:
                        resumen_pcaps[pcap_name]['alerts_global_or'] += 1
                        flujo = extraer_flujo(line, engine)
                        resumen_pcaps[pcap_name]['flows'].add(flujo)

                    # Procesar Motor IPS (Contabilidad interna)
                    if ips_match:
                        ips_id = ips_match.group(1)
                        resumen_pcaps[pcap_name]['alerts_ips'] += 1
                        resumen_pcaps[pcap_name]['ips_ids'].add(ips_id)

                        if ips_id not in stats_ips:
                            stats_ips[ips_id] = 0
                        stats_ips[ips_id] += 1

                    # Procesar Motor APP (Contabilidad interna)
                    if app_match:
                        app_id = app_match.group(1)
                        resumen_pcaps[pcap_name]['alerts_app'] += 1
                        resumen_pcaps[pcap_name]['app_ids'].add(app_id)

                        if app_id not in stats_app:
                            stats_app[app_id] = 0
                        stats_app[app_id] += 1

        except Exception as e:
            print(f"  [!] Error leyendo {filename}: {e}")

    # ==========================================
    # ESCRITURA DE ARCHIVOS CSV
    # ==========================================

    # 1. Resumen Global (CSV_Trafico_XX) - IPS || APP
    resumen_global_csv = os.path.join(out_dir, f"CSV_{traffic_type}_{engine}.csv")
    with open(resumen_global_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['PCAP', 'Alertas_Totales_Unicas'])

        for pcap, data in sorted(resumen_pcaps.items()):
            writer.writerow([
                pcap,
                data['alerts_global_or']
            ])

    # 2. Resumen Detallado por PCAP (Mantiene el desglose interno)
    resumen_csv = os.path.join(out_dir, f"Resumen_{traffic_type}_{engine}.csv")
    with open(resumen_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['PCAP', '#Alertas_Global_Unicas', '#Alertas_IPS', '#Alertas_APP', '#IPS_IDs_Distintos',
                         '#APP_IDs_Distintos',
                         'Lista_IPS_IDs', 'Lista_APP_IDs', '#Flujos'])

        for pcap, data in sorted(resumen_pcaps.items()):
            writer.writerow([
                pcap,
                data['alerts_global_or'],
                data['alerts_ips'],
                data['alerts_app'],
                len(data['ips_ids']),
                len(data['app_ids']),
                ", ".join(sorted(list(data['ips_ids']))),
                ", ".join(sorted(list(data['app_ids']))),
                len(data['flows'])
            ])

    # 3. Diccionario Motor IPS (Simplificado)
    ips_csv = os.path.join(out_dir, f"IPS_{traffic_type}_{engine}.csv")
    with open(ips_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        col_id_name = 'AttackID' if engine == 'FG' else 'ThreatID'
        writer.writerow([col_id_name, 'Apariciones_Totales'])

        # Ordenar por número de apariciones (mayor a menor)
        for ips_id, count in sorted(stats_ips.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ips_id, count])

    # 4. Diccionario Motor APP (Simplificado)
    app_csv = os.path.join(out_dir, f"APP_{traffic_type}_{engine}.csv")
    with open(app_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        col_id_name = 'AppID' if engine == 'FG' else 'AppID'
        writer.writerow([col_id_name, 'Apariciones_Totales'])

        for app_id, count in sorted(stats_app.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([app_id, count])

    print(f"  -> OK. Generados 4 archivos CSV en {out_dir}")


def main():
    # Fijar directorio al script actual
    base_dir = os.path.dirname(os.path.abspath(__file__)) if __file__ else os.getcwd()
    os.chdir(base_dir)

    print("=== TFG: PROCESAMIENTO DE LOGS (FORTIGATE & PALO ALTO) ===")
    print(f"[*] Escaneando desde: {base_dir}\n")

    for engine in ['FG', 'PA']:
        if os.path.exists(engine) and os.path.isdir(engine):
            print(f"\n--- Analizando Firewall: {engine} ---")
            procesar_trafico(engine, "Ataques")
            procesar_trafico(engine, "Legitimo")
        else:
            print(f"\n[!] Carpeta '{engine}' no encontrada. Saltando.")

    print("\n[+] PROCESO COMPLETADO. Todos los CSVs se han generado correctamente.")


if __name__ == '__main__':
    main()