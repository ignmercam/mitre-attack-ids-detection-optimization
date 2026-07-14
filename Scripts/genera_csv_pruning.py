import os
import re
import pandas as pd
from collections import defaultdict


def leer_sids_csv(ruta_csv):
    """Lee un CSV y extrae un set de SIDs de forma robusta."""
    sids = set()
    if os.path.exists(ruta_csv):
        try:
            df = pd.read_csv(ruta_csv)
            col_name = 'SID' if 'SID' in df.columns else df.columns[0]

            for x in df[col_name]:
                if pd.notna(x) and str(x).strip().isdigit():
                    sids.add(int(str(x).strip()))
        except Exception as e:
            print(f"[!] Error leyendo {ruta_csv}: {e}")
    return sids


def get_base_sids(rs_name, priority):
    """Recupera los SIDs base de TP y FP y los cruza con la prioridad elegida."""
    ruta_atk = os.path.join(rs_name, "Ataques", "resultados_logs", f"SIDs_Ataques_{rs_name}.csv")
    ruta_leg = os.path.join(rs_name, "Legitimo", "resultados_logs", f"SIDs_Legitimo_{rs_name}.csv")

    tp_sids = leer_sids_csv(ruta_atk)
    fp_sids = leer_sids_csv(ruta_leg)

    ruta_pri = os.path.join(rs_name, f"Pri{priority}_{rs_name}.csv")
    pri_sids = leer_sids_csv(ruta_pri)

    if pri_sids:
        tp_sids = tp_sids.intersection(pri_sids)
        fp_sids = fp_sids.intersection(pri_sids)

    return tp_sids, fp_sids


def get_removed_sids_from_txt(txt_path):
    """Lee el TXT resumen de la optimización para extraer los SIDs eliminados."""
    data = {}
    if not os.path.exists(txt_path):
        return data

    with open(txt_path, 'r', encoding='utf-8') as f:
        content = f.read()

    blocks_map = {
        "Pruning_500": "[PRUNING 500]",
        "Pruning_1000": "[PRUNING 1000]",
        "Conservative_pruning": "[CONSERVATIVE PRUNING]",
        "Generalized_conservative_pruning": "[500+CONSERVATIVE]",
        "Aggressive_pruning": "[AGRESIVE PRUNING]"
    }

    for csv_name, header in blocks_map.items():
        if header in content:
            blk = content.split(header)[1]
            if '[' in blk:
                blk = blk.split('[')[0]
            try:
                rem_match = re.search(r'Removed SIDs:\s*(.*)', blk)
                if rem_match and rem_match.group(1).strip() != 'None':
                    removed_sids = {int(s.strip()) for s in rem_match.group(1).split(',')}
                else:
                    removed_sids = set()
                data[csv_name] = removed_sids
            except:
                data[csv_name] = set()
        else:
            data[csv_name] = set()

    return data


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__)) if __file__ else os.getcwd()
    os.chdir(base_dir)
    print("=== TFG: PRUNING CSV GENERATOR ===")

    # 1. Menú interactivo para seleccionar entorno
    print("\nSelect the environment to generate CSVs for:")
    print("1. ICS (Evaluates RS1 to RS9)")
    print("2. Enterprise (Evaluates RS1 to RS6)")
    opcion = input("Select an option (1 or 2): ").strip()

    if opcion == '2':
        rulesets = [f"RS{i}" for i in range(1, 7)]
        entorno = "Enterprise"
    else:
        rulesets = [f"RS{i}" for i in range(1, 10)]
        entorno = "ICS"

    print(f"\n[*] Selected Environment: {entorno} ({rulesets[0]} to {rulesets[-1]})")

    master_dir = "Resultados_Snort_GM"
    if not os.path.exists(master_dir):
        print(f"[!] Error: Directory '{master_dir}' not found. Run the optimizer first.")
        return

    out_dir = "CSV_Pruning"
    os.makedirs(out_dir, exist_ok=True)

    csv_phases = ["No_pruning", "Pruning_500", "Pruning_1000", "Conservative_pruning",
                  "Generalized_conservative_pruning", "Aggressive_pruning"]

    # 2. Bucle iterativo por todas las prioridades
    for priority in [4, 3, 2, 1]:
        print(f"\n{'-' * 50}\n[*] Extracting Data for Priority <= {priority}\n{'-' * 50}")

        # Limpiar resultados para cada iteración de prioridad
        results = defaultdict(lambda: defaultdict(dict))

        for rs in rulesets:
            tp_base, fp_base = get_base_sids(rs, priority)
            activos_base = tp_base.union(fp_base)

            folder_path = os.path.join(master_dir, rs, f"Pri_{priority}")
            summary_file = os.path.join(folder_path, "3_Optimization_Summary.txt")

            txt_data = get_removed_sids_from_txt(summary_file) if os.path.exists(summary_file) else {}

            for csv_name in csv_phases:
                if not activos_base:
                    results[csv_name][rs] = {"tp_sids": [], "fp_sids": []}
                    continue

                if csv_name == "No_pruning":
                    sids_mantenidos = set(activos_base)
                else:
                    if csv_name in txt_data:
                        sids_mantenidos = activos_base - txt_data[csv_name]
                    else:
                        sids_mantenidos = set()

                tp_mantenidos = sids_mantenidos.intersection(tp_base)
                fp_mantenidos = sids_mantenidos.intersection(fp_base)

                results[csv_name][rs] = {
                    "tp_sids": sorted(list(tp_mantenidos)),
                    "fp_sids": sorted(list(fp_mantenidos))
                }

        # 3. Escribir los CSVs con cabeceras en Inglés y sufijo de Prioridad
        columnas = ['Metric'] + rulesets

        for csv_name in csv_phases:
            # Añadimos el sufijo _Pri_X al archivo
            out_csv = os.path.join(out_dir, f"{csv_name}_Pri_{priority}.csv")

            fila_tp_lista = ['Maintained TP SIDs List']
            fila_tp_count = ['# Maintained TP SIDs']
            fila_fp_lista = ['Maintained FP SIDs List']
            fila_fp_count = ['# Maintained FP SIDs']

            for rs in rulesets:
                tp_list = results[csv_name][rs].get('tp_sids', [])
                fp_list = results[csv_name][rs].get('fp_sids', [])

                fila_tp_lista.append(", ".join(map(str, tp_list)))
                fila_tp_count.append(len(tp_list))

                fila_fp_lista.append(", ".join(map(str, fp_list)))
                fila_fp_count.append(len(fp_list))

            df = pd.DataFrame([fila_tp_lista, fila_tp_count, fila_fp_lista, fila_fp_count], columns=columnas)
            df.to_csv(out_csv, index=False, encoding='utf-8')
            print(f"  -> Generated: {out_csv}")

    print(f"\n✅ Success! All {len(csv_phases) * 4} CSV files saved in '{out_dir}'.")


if __name__ == "__main__":
    main()