import os
import re
import csv
import pandas as pd
from collections import Counter

def logica_resultados_ruleset(input_dir, rs_number, tipo):
    """
    Procesa logs y genera CSVs en la carpeta resultados_logs.
    'tipo' debe ser 'Ataques' o 'Legitimo'.
    """
    rs_suffix = f"_RS{rs_number}"
    output_dir = os.path.join(input_dir, 'resultados_logs')
    os.makedirs(output_dir, exist_ok=True)

    global_file_stats = []
    global_sid_counter = Counter()
    sid_pattern = re.compile(r'\[\*\*\]\s+\[\d+:(\d+):\d+\]')

    for filename in os.listdir(input_dir):
        if not filename.endswith('.log'):
            continue

        # 1. NOMBRE EXACTO: Sin recortes para evitar que se sobrescriban
        base_name = os.path.splitext(filename)[0]

        file_path = os.path.join(input_dir, filename)
        file_sid_counter = Counter()
        total_alerts = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = sid_pattern.search(line)
                    if match:
                        sid = match.group(1)
                        file_sid_counter[sid] += 1
                        global_sid_counter[sid] += 1
                        total_alerts += 1
        except Exception as e:
            print(f"Error leyendo el archivo {filename}: {e}")
            continue

        # 2. GUARDAMOS TODOS: Tengan alertas o tengan 0 alertas
        global_file_stats.append([base_name, total_alerts])

        individual_csv_path = os.path.join(output_dir, f"SIDs_{base_name}{rs_suffix}.csv")
        with open(individual_csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['SID', 'Apariciones_Totales'])
            for sid, count in sorted(file_sid_counter.items(), key=lambda item: item[1], reverse=True):
                writer.writerow([sid, count])

    csv_rsx_path = os.path.join(output_dir, f'CSV{rs_suffix}.csv')
    with open(csv_rsx_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Nombre_PCAP', 'Alertas_Totales'])
        for stat in global_file_stats:
            writer.writerow(stat)

    sids_global_path = os.path.join(output_dir, f'SIDs_{tipo}{rs_suffix}.csv')
    with open(sids_global_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['SID', 'Apariciones_Totales'])
        for sid, count in sorted(global_sid_counter.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([sid, count])


def logica_reporte_ataques(input_dir, rs_number):
    rs_suffix = f"_RS{rs_number}"
    res_logs_dir = os.path.join(input_dir, 'resultados_logs')
    csv_global = os.path.join(res_logs_dir, f'CSV{rs_suffix}.csv')

    if not os.path.exists(csv_global):
        return

    alertas_totales_dict = {}
    with open(csv_global, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            alertas_totales_dict[row['Nombre_PCAP']] = row['Alertas_Totales']

    datos_excel = []
    for filename in os.listdir(res_logs_dir):
        if filename.startswith('SIDs_') and filename.endswith(f'{rs_suffix}.csv'):
            # Ignoramos los archivos globales
            if filename.startswith('SIDs_Ataques') or filename.startswith('SIDs_Legitimo'):
                continue

            base_name = filename.replace('SIDs_', '').replace(f'{rs_suffix}.csv', '')
            ruta_sids = os.path.join(res_logs_dir, filename)

            sids_list = []
            with open(ruta_sids, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sids_list.append((row['SID'], row['Apariciones_Totales']))

            alertas_totales = alertas_totales_dict.get(base_name, 0)
            alertas_sid_str = ", ".join([f"{sid} ({count})" for sid, count in sids_list])
            sids_sin_rep = ", ".join([sid for sid, _ in sids_list])

            datos_excel.append({
                'Ataque': base_name,
                '# Alertas': int(alertas_totales),
                '# Alertas/SID': alertas_sid_str,
                'SIDs sin repeticion': sids_sin_rep,
                '# SID': len(sids_list)
            })

    if datos_excel:
        df = pd.DataFrame(datos_excel)
        # Ordenación alfabética
        df = df.sort_values(by='Ataque')

        ruta_excel = os.path.join(res_logs_dir, f'Resumen_Ataques{rs_suffix}.xlsx')
        df.to_excel(ruta_excel, index=False)


def logica_reporte_legitimo(input_dir, rs_number):
    sid_pattern = re.compile(r'\[\*\*\]\s+\[\d+:(\d+):\d+\]')
    total_sid_counter = Counter()
    total_alerts = 0
    archivos = 0

    for filename in os.listdir(input_dir):
        if not filename.endswith('.log'): continue
        archivos += 1
        with open(os.path.join(input_dir, filename), 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = sid_pattern.search(line)
                if match:
                    total_sid_counter[match.group(1)] += 1
                    total_alerts += 1

    if archivos > 0:
        sids_ordenados = sorted(total_sid_counter.items(), key=lambda item: item[1])
        datos_excel = [{
            'Ataque': 'Tráfico Legítimo',
            '# Alertas': int(total_alerts),
            '# Alertas/SID': ", ".join([f"{s} ({c})" for s, c in sids_ordenados]),
            'SIDs sin repeticion': ", ".join([s for s, _ in sids_ordenados]),
            '# SID': len(total_sid_counter)
        }]

        df = pd.DataFrame(datos_excel)
        ruta_excel = os.path.join(input_dir, f'Resumen_FP_RS{rs_number}.xlsx')
        df.to_excel(ruta_excel, index=False)


def logica_flujos(input_dir):
    sid_pattern = re.compile(r'\[\*\*\]\s+\[\d+:\d+:\d+\]')
    flujos_unicos_globales = set()
    archivos = 0

    for filename in os.listdir(input_dir):
        if not filename.endswith('.log'): continue
        archivos += 1
        with open(os.path.join(input_dir, filename), 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if sid_pattern.search(line):
                    parts = line.strip().split()
                    if '->' in parts:
                        idx = parts.index('->')
                        if idx >= 2 and idx + 1 < len(parts):
                            protocolo = parts[idx - 2].strip('{}')
                            src = parts[idx - 1]
                            dst = parts[idx + 1]
                            ep1, ep2 = sorted([src, dst])
                            flujos_unicos_globales.add((protocolo, ep1, ep2))

    if archivos > 0:
        total_flujos = len(flujos_unicos_globales)
        ruta_txt = os.path.join(input_dir, 'flujos_detectados.txt')
        with open(ruta_txt, "w", encoding="utf-8") as f:
            f.write(f"{total_flujos}")


# --- ORQUESTADOR ---

def procesar_ruleset(path, rs_number):
    print(f"\n[{path}] Procesando escenario...")

    dir_ataques = os.path.join(path, "Ataques")
    dir_legitimo = os.path.join(path, "Legitimo")

    # 1. Procesar LEGÍTIMO
    if os.path.exists(dir_legitimo):
        print(f"  [+] Analizando Tráfico Legítimo...")
        logica_resultados_ruleset(dir_legitimo, rs_number, "Legitimo")
        logica_reporte_legitimo(dir_legitimo, rs_number)
        logica_flujos(dir_legitimo)

    # 2. Procesar ATAQUES
    if os.path.exists(dir_ataques):
        print(f"  [+] Analizando Tráfico de Ataques...")
        logica_resultados_ruleset(dir_ataques, rs_number, "Ataques")
        logica_reporte_ataques(dir_ataques, rs_number)


def main():
    print("=== ASISTENTE DE ANÁLISIS DE RULESETS TFG (FASE 1) ===")
    print("1. Procesar un RS concreto (ej. RS3)")
    print("2. Barrido completo (Sweep)")
    opcion = input("Selecciona una opción: ")

    if opcion == '1':
        rs_num = input("Número del RS: ").strip()
        path = f"RS{rs_num}"
        if os.path.exists(path):
            procesar_ruleset(path, rs_num)
        else:
            print(f"Error: No existe la carpeta {path}")

    elif opcion == '2':
        folders = sorted([d for d in os.listdir('.') if os.path.isdir(d) and d.startswith('RS')],
                         key=lambda x: int(re.findall(r'\d+', x)[0]))
        if not folders:
            print("No se han encontrado carpetas RSX.")
            return
        for folder in folders:
            rs_num = re.findall(r'\d+', folder)[0]
            procesar_ruleset(folder, rs_num)
    else:
        print("Opción inválida.")


if __name__ == "__main__":
    main()