import os
import re
import pandas as pd
import math
from collections import defaultdict, Counter


def calc_metrics(test_sids, atk_data_pcap, leg_data_flow, total_atk_pcaps, total_leg_flows,
                 atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts):
    """
    Calcula TP/FN basados en PCAPs.
    Calcula TN/FP basados en Flujos (Lógica Original).
    Calcula Alertas Crudas basadas en recuento exacto.
    Calcula Alertas Diferentes/Flujo matemáticamente.
    """
    tp = sum(1 for pcap_sids in atk_data_pcap.values() if not pcap_sids.isdisjoint(test_sids))
    fn = total_atk_pcaps - tp
    tpr = tp / total_atk_pcaps if total_atk_pcaps > 0 else 0.0

    fp = sum(1 for flow_sids in leg_data_flow.values() if not flow_sids.isdisjoint(test_sids))
    tn = total_leg_flows - fp
    tnr = tn / total_leg_flows if total_leg_flows > 0 else 0.0

    gm = math.sqrt(tpr * tnr)

    alerts_tp = sum(atk_alert_counts[sid] for sid in test_sids)
    alerts_fp = sum(leg_alert_counts[sid] for sid in test_sids)

    alerts_tp_diff = sum(atk_diff_counts[sid] for sid in test_sids)
    alerts_fp_diff = sum(leg_diff_counts[sid] for sid in test_sids)

    return tp, fn, tn, fp, tpr, tnr, gm, alerts_tp, alerts_fp, alerts_tp_diff, alerts_fp_diff


def export_removed_sids(filename, removed_set):
    """Crea un csv con los SIDs eliminados."""
    sorted_sids = sorted(list(removed_set), key=lambda x: int(x) if str(x).isdigit() else 0)
    df = pd.DataFrame({'Removed_SID': sorted_sids})
    df.to_csv(filename, index=False)


def report_block(rf, title, test_sids, removed_ids, atk_data_pcap, leg_data_flow, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS,
                 atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts):
    """Escribe las métricas de un escenario concreto en el TXT resumen."""
    metrics = calc_metrics(test_sids, atk_data_pcap, leg_data_flow, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS,
                           atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts)
    tp, fn, tn, fp, tpr, tnr, gm, a_tp, a_fp, a_tp_d, a_fp_d = metrics
    usab = round(a_fp / a_tp, 4) if a_tp > 0 else 0.0

    rf.write(f"[{title}]\n")
    rf.write(f"Active Rules: {len(test_sids)}\n")
    sorted_removed = sorted(list(removed_ids), key=lambda x: int(x) if str(x).isdigit() else 0)
    rf.write(f"Removed SIDs: {', '.join(str(s) for s in sorted_removed) if removed_ids else 'None'}\n")
    rf.write(f"Detection Rate (PCAPs): {tpr:.6f}\n")
    rf.write(f"Raw Alerts (Attacks): {a_tp}\n")
    rf.write(f"Diff Alerts/Flow (Attacks): {a_tp_d}\n")
    rf.write(f"Raw Alerts (Legitimate): {a_fp}\n")
    rf.write(f"Diff Alerts/Flow (Legitimate): {a_fp_d}\n")
    rf.write(f"Raw Alerts (Total): {a_tp + a_fp}\n")
    rf.write(f"Usability (FP_Alerts/TP_Alerts): {usab}\n")
    rf.write(f"G-Mean: {gm:.6f}\n\n")


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__)) if __file__ else os.getcwd()
    os.chdir(base_dir)
    print("=== TFG: SNORT RULES G-MEAN OPTIMIZER (v3 - Diff/Flow Dynamic Sort) ===\n")

    TOTAL_ATK_PCAPS = 110
    TOTAL_LEG_FLOWS = 78694206

    regex_sid = re.compile(r'\[\*\*\]\s+\[\d+:(\d+):\d+\]')
    regex_prio = re.compile(r'\[Priority:\s*(\d+)\]', re.IGNORECASE)
    regex_flujo = re.compile(r'\{(.*?)\}\s+(\S+)\s+->\s+(\S+)')

    carpetas_rs = [d for d in os.listdir('.') if os.path.isdir(d) and d.startswith('RS')]
    carpetas_rs = sorted(carpetas_rs,
                         key=lambda x: int(re.findall(r'\d+', x)[0]) if re.findall(r'\d+', x) else 0)

    master_out_dir = "Resultados_Snort_GM"
    os.makedirs(master_out_dir, exist_ok=True)

    for rs in carpetas_rs:
        print(f"{'=' * 50}\nProcessing {rs}...\n{'=' * 50}")

        atk_master_dict = defaultdict(list)
        atk_master_flows = defaultdict(list)  # TRACKEO PARA FLUJOS EN ATAQUE
        leg_master_dict = defaultdict(list)

        # --- A) LEER LISTA EXTERNA DE SIDs ORDENADA ---
        ordered_sids_from_csv = []
        sids_csv_path = os.path.join(rs, "Ataques", "resultados_logs", f"SIDs_Ataques_{rs}.csv")

        if os.path.exists(sids_csv_path):
            try:
                df_sids = pd.read_csv(sids_csv_path)
                col_name = 'SID' if 'SID' in df_sids.columns else df_sids.columns[0]
                ordered_sids_from_csv = df_sids[col_name].astype(str).str.strip().tolist()
                print(f"  [+] Loaded {len(ordered_sids_from_csv)} SIDs from '{sids_csv_path}'")
            except Exception as e:
                print(f"  [!] Error reading {sids_csv_path}: {e}")

        # --- B) LEER LOGS ATAQUE ---
        ruta_ataques = os.path.join(rs, "Ataques")
        if os.path.exists(ruta_ataques):
            for f in os.listdir(ruta_ataques):
                if f.endswith('.log') or f.endswith('.txt'):
                    pcap_name = f.replace('.log', '').replace('.txt', '')
                    with open(os.path.join(ruta_ataques, f), 'r', errors='ignore') as file:
                        for line in file:
                            m_sid = regex_sid.search(line)
                            m_pri = regex_prio.search(line)
                            if m_sid and m_pri:
                                sid = m_sid.group(1)
                                pri = int(m_pri.group(1))
                                atk_master_dict[pcap_name].append((sid, pri))

                                # Extraer Flujo en Ataques (Para la nueva métrica Diferentes/Flujo)
                                m_flujo = regex_flujo.search(line)
                                if m_flujo:
                                    proto = m_flujo.group(1).strip()
                                    src = m_flujo.group(2).strip()
                                    dst = m_flujo.group(3).strip()
                                    ep1, ep2 = sorted([src, dst])
                                    flow_id = f"{proto} {ep1} <-> {ep2}"
                                else:
                                    flow_id = line.strip()
                                unique_flow_id = f"{pcap_name}__{flow_id}"
                                atk_master_flows[unique_flow_id].append((sid, pri))

        # --- C) LEER LOGS LEGÍTIMO ---
        ruta_legitimo = os.path.join(rs, "Legitimo")
        if os.path.exists(ruta_legitimo):
            for f in os.listdir(ruta_legitimo):
                if f.endswith('.log') or f.endswith('.txt'):
                    pcap_leg = f.replace('.log', '').replace('.txt', '')
                    with open(os.path.join(ruta_legitimo, f), 'r', errors='ignore') as file:
                        for line in file:
                            m_sid = regex_sid.search(line)
                            m_pri = regex_prio.search(line)
                            m_flujo = regex_flujo.search(line)
                            if m_sid and m_pri:
                                sid = m_sid.group(1)
                                pri = int(m_pri.group(1))

                                if m_flujo:
                                    proto = m_flujo.group(1).strip()
                                    src = m_flujo.group(2).strip()
                                    dst = m_flujo.group(3).strip()
                                    ep1, ep2 = sorted([src, dst])
                                    flow_id = f"{proto} {ep1} <-> {ep2}"
                                else:
                                    flow_id = line.strip()

                                unique_flow_id = f"{pcap_leg}__{flow_id}"
                                leg_master_dict[unique_flow_id].append((sid, pri))

        # --- ITERAR POR LOS 4 ESCENARIOS DE PRIORIDAD ---
        escenarios = [4, 3, 2, 1]

        for pri_limit in escenarios:
            print(f"\n  [*] Starting Scenario: Priority <= {pri_limit}")

            out_dir = os.path.join(master_out_dir, rs, f"Pri_{pri_limit}")
            os.makedirs(out_dir, exist_ok=True)

            detailed_log_path = os.path.join(out_dir, "4_Detailed_Execution_Log.txt")

            with open(detailed_log_path, 'w', encoding='utf-8') as log_f:
                log_f.write(f"=== START GM OPTIMIZATION - {rs} (Priority <= {pri_limit}) ===\n\n")

                # 1. Filtrar por prioridad y armar estructuras
                atk_filtered = defaultdict(set)
                atk_alert_counts = Counter()
                for pcap, eventos in atk_master_dict.items():
                    for sid, prio in eventos:
                        if prio <= pri_limit:
                            atk_filtered[pcap].add(sid)
                            atk_alert_counts[sid] += 1

                atk_filtered_flows = defaultdict(set)
                for flow_id, eventos in atk_master_flows.items():
                    for sid, prio in eventos:
                        if prio <= pri_limit:
                            atk_filtered_flows[flow_id].add(sid)

                leg_filtered = defaultdict(set)
                leg_alert_counts = Counter()
                for flow_id, eventos in leg_master_dict.items():
                    for sid, prio in eventos:
                        if prio <= pri_limit:
                            leg_filtered[flow_id].add(sid)
                            leg_alert_counts[sid] += 1

                # 2. Pre-cálculo de "Different Alerts/Flow"
                atk_diff_counts = Counter()
                for sids in atk_filtered_flows.values():
                    for sid in sids:
                        atk_diff_counts[sid] += 1

                leg_diff_counts = Counter()
                for sids in leg_filtered.values():
                    for sid in sids:
                        leg_diff_counts[sid] += 1

                sids_ataque = set(sid for sids in atk_filtered.values() for sid in sids)
                sids_legitimo = set(sid for sids in leg_filtered.values() for sid in sids)
                sids_activos = sids_ataque.union(sids_legitimo)

                if not sids_activos:
                    print("      -> Skip: No active rules.")
                    continue

                # =============================================================
                # GENERACIÓN DE LAS FASES DE PRUNING PARALELAS Y SECUENCIALES
                # =============================================================

                # --- PRE-CONSERVATIVE PRUNING 500 ---
                sids_pre500 = {s for s in sids_activos if leg_diff_counts[s] <= 500}
                removed_pre500 = sids_activos - sids_pre500
                export_removed_sids(os.path.join(out_dir, "1a_PreCons_Pruning500_Removed.csv"), removed_pre500)

                # --- PRE-CONSERVATIVE PRUNING 1000 ---
                sids_pre1000 = {s for s in sids_activos if leg_diff_counts[s] <= 1000}
                removed_pre1000 = sids_activos - sids_pre1000
                export_removed_sids(os.path.join(out_dir, "1b_PreCons_Pruning1000_Removed.csv"), removed_pre1000)

                # --- CONSERVATIVE PRUNING ---
                ids_fp_exclusivos = sids_legitimo - sids_ataque
                sids_cons = sids_activos - ids_fp_exclusivos
                export_removed_sids(os.path.join(out_dir, "1c_Phase1_Exclusive_FP_Removed.csv"), ids_fp_exclusivos)

                # --- POST-CONSERVATIVE PRUNING 500 ---
                sids_post500 = {s for s in sids_cons if leg_diff_counts[s] <= 500}
                removed_post500_extra = sids_cons - sids_post500
                removed_post500_total = ids_fp_exclusivos | removed_post500_extra
                export_removed_sids(os.path.join(out_dir, "1c_PostCons_Pruning500_Removed.csv"),
                                    removed_post500_total)

                # --- POST-CONSERVATIVE PRUNING 1000 ---
                sids_post1000 = {s for s in sids_cons if leg_diff_counts[s] <= 1000}
                removed_post1000_extra = sids_cons - sids_post1000
                removed_post1000_total = ids_fp_exclusivos | removed_post1000_extra
                export_removed_sids(os.path.join(out_dir, "1d_PostCons_Pruning1000_Removed.csv"),
                                    removed_post1000_total)

                # --- AGRESIVE PRUNING (Fase 2 por Alertas Different/Flow) ---
                log_f.write("=== PHASE 2: DIFFERENT ALERTS/FLOW SORTED OPTIMIZATION (G-MEAN) ===\n")
                # Filtramos las reglas mixtas y las ordenamos de mayor a menor según su impacto en flujos legítimos (Different/Flow)
                mixed_sids = [sid for sid in sids_activos if sid in sids_ataque and sid in sids_legitimo]
                candidate_sids = sorted(mixed_sids, key=lambda sid: leg_diff_counts[sid], reverse=True)

                history = []
                current_sids = set(sids_cons)
                gm_ini = calc_metrics(current_sids, atk_filtered, leg_filtered, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS,
                                      atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts)[6]
                current_gm = gm_ini
                iteration_count = 1

                for sid in candidate_sids:
                    test_sids = current_sids - {sid}
                    m_tp, m_fn, m_tn, m_fp, m_tpr, m_tnr, m_gm, m_a_tp, m_a_fp, m_a_tp_d, m_a_fp_d = calc_metrics(
                        test_sids, atk_filtered, leg_filtered, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS,
                        atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts)

                    log_f.write(f"Iteration {iteration_count}:\n")
                    log_f.write(f"  Evaluating SID {sid} -> GM: {m_gm:.6f}\n")

                    if m_gm > current_gm:
                        current_sids.remove(sid)
                        current_gm = m_gm
                        log_f.write(f"  [+] IMPROVEMENT FOUND: Removed SID {sid}. New GM: {current_gm:.6f}\n\n")

                        history.append({
                            'Step': iteration_count, 'Removed_SID': sid,
                            'TP_PCAPs': m_tp, 'FN_PCAPs': m_fn, 'TN_Flows': m_tn, 'FP_Flows': m_fp,
                            'TPR': round(m_tpr, 6), 'TNR': round(m_tnr, 6), 'G-Mean': round(m_gm, 6),
                            'Alerts_TP': m_a_tp, 'Alerts_FP': m_a_fp, 'Alerts_TP_Diff': m_a_tp_d,
                            'Alerts_FP_Diff': m_a_fp_d, 'Total_Alerts': m_a_tp + m_a_fp
                        })
                    else:
                        log_f.write(f"  [-] No improvement. Keeping SID {sid}.\n\n")
                    iteration_count += 1

                removed_agresive_total = sids_activos - current_sids

                if history:
                    df_steps = pd.DataFrame(history)
                    df_steps.to_csv(os.path.join(out_dir, "2_GM_Optimization_Steps.csv"), index=False)
                else:
                    cols = ['Step', 'Removed_SID', 'TP_PCAPs', 'FN_PCAPs', 'TN_Flows', 'FP_Flows',
                            'TPR', 'TNR', 'G-Mean', 'Alerts_TP', 'Alerts_FP', 'Alerts_TP_Diff', 'Alerts_FP_Diff',
                            'Total_Alerts']
                    pd.DataFrame(columns=cols).to_csv(os.path.join(out_dir, "2_GM_Optimization_Steps.csv"), index=False)

                log_f.write("=== FINAL SUMMARY ===\n")
                log_f.write(f"Final Active SIDs: {len(current_sids)}\n")
                log_f.write(f"Final GM Optimal: {current_gm:.6f}\n")

                # --- 3. RELLENAR REPORTE GLOBAL TXT ---
                report_path = os.path.join(out_dir, "3_Optimization_Summary.txt")
                with open(report_path, "w", encoding="utf-8") as rf:
                    rf.write("=== G-MEAN OPTIMIZATION SUMMARY ===\n")
                    rf.write(f"Ruleset: {rs}\n")
                    rf.write(f"Scenario: Priority <= {pri_limit}\n")
                    rf.write("Method: External CSV Ordered Backward Elimination + Static Pruning\n\n")

                    report_block(rf, "PRUNING 500", sids_pre500, removed_pre500, atk_filtered, leg_filtered,
                                 TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                 atk_diff_counts, leg_diff_counts)
                    report_block(rf, "PRUNING 1000", sids_pre1000, removed_pre1000, atk_filtered, leg_filtered,
                                 TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                 atk_diff_counts, leg_diff_counts)
                    report_block(rf, "CONSERVATIVE PRUNING", sids_cons, ids_fp_exclusivos, atk_filtered, leg_filtered,
                                 TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                 atk_diff_counts, leg_diff_counts)
                    report_block(rf, "500+CONSERVATIVE", sids_post500, removed_post500_total, atk_filtered,
                                 leg_filtered, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts,
                                 leg_alert_counts, atk_diff_counts, leg_diff_counts)
                    report_block(rf, "1000+CONSERVATIVE", sids_post1000, removed_post1000_total, atk_filtered,
                                 leg_filtered, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts,
                                 leg_alert_counts, atk_diff_counts, leg_diff_counts)
                    report_block(rf, "AGRESIVE PRUNING", current_sids, removed_agresive_total, atk_filtered,
                                 leg_filtered, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts,
                                 leg_alert_counts, atk_diff_counts, leg_diff_counts)

    print("\n✅ OPTIMIZACIÓN COMPLETADA. Revisa la carpeta 'Resultados_Snort_GM'.")


if __name__ == "__main__":
    main()