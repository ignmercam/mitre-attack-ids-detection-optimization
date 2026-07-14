import os
import re
import math
import pandas as pd
from collections import defaultdict, Counter

# ======================================================================
# TFG: FG / PA G-MEAN OPTIMIZER — v6 (INCLUSIÓN/EXCLUSIÓN DE ALERTAS DOBLES)
# ======================================================================

FG_SEV_MAP = {'info': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
FG_RISK_MAP = {'information': 1, 'low': 2, 'medium': 3, 'high': 4, 'elevated': 5}

ENGINE_REGEX = {
    'FG': {
        'traffic_line': re.compile(r'type=["\']?traffic["\']?', re.IGNORECASE),
        'session': re.compile(r'sessionid=[\'"]?(\d+)', re.IGNORECASE),
        'ips_id': re.compile(r'attackid=[\'"]?(\d+)', re.IGNORECASE),
        'ips_sev': re.compile(r'severity=[\'"]?([a-zA-Z]+)', re.IGNORECASE),
        'app_id': re.compile(r'appid=[\'"]?(\d+)', re.IGNORECASE),
        'app_sev': re.compile(r'apprisk=[\'"]?([a-zA-Z]+)', re.IGNORECASE),
    },
    'PA': {
        'traffic_line': re.compile(r'log_type=["\']?TRAFFIC["\']?', re.IGNORECASE),
        'session': re.compile(r'sessionid=[\'"]?(\d+)', re.IGNORECASE),
        'ips_id': re.compile(r'threat_id=[\'"]?([^"\'\s,]+)', re.IGNORECASE),
        'ips_sev': re.compile(r'severity_number=[\'"]?(\d+)', re.IGNORECASE),
        'app_id': re.compile(r'(?:appid|app)=[\'"]?([^"\'\s,]+)', re.IGNORECASE),
        'app_sev': re.compile(r'risk_of_app=[\'"]?(\d+)', re.IGNORECASE),
    }
}


def extract_pa_threat_id(raw_id):
    m = re.search(r'\((\d+)\)', raw_id)
    if m:
        return m.group(1)
    m2 = re.search(r'(\d+)', raw_id)
    if m2:
        return m2.group(1)
    return raw_id


def parse_line(line, engine, regexes):
    if regexes['traffic_line'].search(line):
        return None

    m_sess = regexes['session'].search(line)
    session_id = m_sess.group(1) if m_sess else None

    m_ips_id = regexes['ips_id'].search(line)
    m_ips_sev = regexes['ips_sev'].search(line)
    ips_id, ips_level = None, 0
    if m_ips_id and m_ips_sev:
        raw_id = m_ips_id.group(1)
        ips_id = extract_pa_threat_id(raw_id) if engine == 'PA' else raw_id
        sev_raw = m_ips_sev.group(1).lower()
        ips_level = FG_SEV_MAP.get(sev_raw, 0) if engine == 'FG' else (
            int(sev_raw) if sev_raw.isdigit() else 0)
        if ips_level == 0:
            ips_id = None

    m_app_id = regexes['app_id'].search(line)
    m_app_sev = regexes['app_sev'].search(line)
    app_id, app_level = None, 0
    if m_app_id and m_app_sev:
        app_id = m_app_id.group(1)
        sev_raw = m_app_sev.group(1).lower()
        app_level = FG_RISK_MAP.get(sev_raw, 0) if engine == 'FG' else (
            int(sev_raw) if sev_raw.isdigit() else 0)
        if app_level == 0:
            app_id = None

    if ips_id is None and app_id is None:
        return None

    return session_id, ips_id, ips_level, app_id, app_level


def read_engine_folder(base_path, engine, regexes):
    atk_pcap_lines = defaultdict(list)
    leg_lines = []

    ruta_atk = os.path.join(base_path, "Ataques")
    if os.path.exists(ruta_atk):
        for fname in os.listdir(ruta_atk):
            if not (fname.endswith('.log') or fname.endswith('.txt')):
                continue
            pcap_name = fname.replace('.log', '').replace('.txt', '')
            with open(os.path.join(ruta_atk, fname), 'r', errors='ignore') as f:
                for line in f:
                    parsed = parse_line(line, engine, regexes)
                    if parsed is None:
                        continue
                    session_id, ips_id, ips_level, app_id, app_level = parsed
                    flow_key = f"{pcap_name}__sess_{session_id}" if session_id else f"{pcap_name}__NO_SESSION"
                    atk_pcap_lines[pcap_name].append((flow_key, ips_id, ips_level, app_id, app_level))

    ruta_leg = os.path.join(base_path, "Legitimo")
    if os.path.exists(ruta_leg):
        for root, dirs, files in os.walk(ruta_leg):
            for fname in files:
                if not (fname.endswith('.log') or fname.endswith('.txt')):
                    continue
                with open(os.path.join(root, fname), 'r', errors='ignore') as f:
                    for line in f:
                        parsed = parse_line(line, engine, regexes)
                        if parsed is None:
                            continue
                        session_id, ips_id, ips_level, app_id, app_level = parsed
                        flow_key = f"{fname}__sess_{session_id}" if session_id else f"{fname}__NO_SESSION"
                        leg_lines.append((flow_key, ips_id, ips_level, app_id, app_level))

    return atk_pcap_lines, leg_lines


def build_scenario_structures(atk_pcap_lines, leg_lines, scenario, track):
    def filtro(ips_id, ips_level, app_id, app_level):
        v_i = ips_id if (ips_id and ips_level >= scenario) else None
        v_a = app_id if (app_id and app_level >= scenario) else None
        if track == 'IPS':
            return v_i, None
        else:
            return v_i, v_a

    atk_data_pcap = defaultdict(set)
    atk_data_flow = defaultdict(set)
    atk_alert_counts = Counter()
    atk_diff_seen = defaultdict(set)
    atk_line_co_occur = Counter()

    for pcap, lineas in atk_pcap_lines.items():
        for flow_key, ips_id, ips_level, app_id, app_level in lineas:
            v_i, v_a = filtro(ips_id, ips_level, app_id, app_level)
            is_dummy = flow_key.endswith("__NO_SESSION")

            if v_i is not None and v_a is not None:
                atk_line_co_occur[tuple(sorted((str(v_i), str(v_a))))] += 1

            for v in (v_i, v_a):
                if v is None:
                    continue
                atk_data_pcap[pcap].add(v)
                atk_alert_counts[v] += 1
                if not is_dummy:
                    atk_data_flow[flow_key].add(v)
                    atk_diff_seen[flow_key].add(v)

    atk_diff_counts = Counter()
    for ids in atk_diff_seen.values():
        for v in ids:
            atk_diff_counts[v] += 1

    leg_data_flow = defaultdict(set)
    leg_alert_counts = Counter()
    leg_diff_seen = defaultdict(set)
    leg_line_co_occur = Counter()

    for flow_key, ips_id, ips_level, app_id, app_level in leg_lines:
        v_i, v_a = filtro(ips_id, ips_level, app_id, app_level)
        is_dummy = flow_key.endswith("__NO_SESSION")

        if v_i is not None and v_a is not None:
            leg_line_co_occur[tuple(sorted((str(v_i), str(v_a))))] += 1

        for v in (v_i, v_a):
            if v is None:
                continue
            leg_alert_counts[v] += 1
            if not is_dummy:
                leg_data_flow[flow_key].add(v)
                leg_diff_seen[flow_key].add(v)

    leg_diff_counts = Counter()
    for ids in leg_diff_seen.values():
        for v in ids:
            leg_diff_counts[v] += 1

    return (atk_data_pcap, atk_data_flow, leg_data_flow,
            atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts,
            atk_line_co_occur, leg_line_co_occur)


def calc_metrics(test_ids, atk_data_pcap, leg_data_flow, total_atk_pcaps, total_leg_flows,
                 atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts,
                 atk_line_co_occur=None, leg_line_co_occur=None):
    tp = sum(1 for pcap_ids in atk_data_pcap.values() if not pcap_ids.isdisjoint(test_ids))
    fn = total_atk_pcaps - tp
    tpr = tp / total_atk_pcaps if total_atk_pcaps > 0 else 0.0

    fp = sum(1 for flow_ids in leg_data_flow.values() if not flow_ids.isdisjoint(test_ids))
    tn = total_leg_flows - fp
    tnr = tn / total_leg_flows if total_leg_flows > 0 else 0.0

    gm = math.sqrt(tpr * tnr)

    alerts_tp = sum(atk_alert_counts[i] for i in test_ids)
    alerts_fp = sum(leg_alert_counts[i] for i in test_ids)

    if atk_line_co_occur:
        for (id1, id2), overlap_count in atk_line_co_occur.items():
            if id1 in test_ids and id2 in test_ids:
                alerts_tp -= overlap_count

    if leg_line_co_occur:
        for (id1, id2), overlap_count in leg_line_co_occur.items():
            if id1 in test_ids and id2 in test_ids:
                alerts_fp -= overlap_count

    alerts_tp_diff = sum(atk_diff_counts[i] for i in test_ids)
    alerts_fp_diff = sum(leg_diff_counts[i] for i in test_ids)

    return tp, fn, tn, fp, tpr, tnr, gm, alerts_tp, alerts_fp, alerts_tp_diff, alerts_fp_diff


def sort_key_id(x):
    s = str(x)
    return (0, int(s)) if s.isdigit() else (1, s)


def export_removed_ids(filename, removed_set):
    sorted_ids = sorted(removed_set, key=sort_key_id)
    pd.DataFrame({'Removed_ID': sorted_ids}).to_csv(filename, index=False)


def report_block(rf, title, test_ids, removed_ids, atk_data_pcap, leg_data_flow,
                 total_atk_pcaps, total_leg_flows, atk_alert_counts, leg_alert_counts,
                 atk_diff_counts, leg_diff_counts, atk_line_co_occur, leg_line_co_occur):
    metrics = calc_metrics(test_ids, atk_data_pcap, leg_data_flow, total_atk_pcaps, total_leg_flows,
                           atk_alert_counts, leg_alert_counts, atk_diff_counts, leg_diff_counts,
                           atk_line_co_occur, leg_line_co_occur)
    tp, fn, tn, fp, tpr, tnr, gm, a_tp, a_fp, a_tp_d, a_fp_d = metrics
    usab = round(a_fp / a_tp, 4) if a_tp > 0 else 0.0

    rf.write(f"[{title}]\n")
    rf.write(f"Active IDs: {len(test_ids)}\n")
    sorted_removed = sorted(removed_ids, key=sort_key_id)
    rf.write(f"Removed IDs: {', '.join(str(s) for s in sorted_removed) if removed_ids else 'None'}\n")
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
    print("=== TFG: FG-PA G-MEAN OPTIMIZER (v6) ===\n")

    TOTAL_ATK_PCAPS = 110
    TOTAL_LEG_FLOWS = 78694206

    master_out_dir = "Resultados_FG-PA_GM"
    os.makedirs(master_out_dir, exist_ok=True)

    for engine in ['FG', 'PA']:
        if not os.path.exists(engine):
            continue

        print(f"[*] Leyendo logs de {engine}...")
        atk_pcap_lines, leg_lines = read_engine_folder(engine, engine, ENGINE_REGEX[engine])
        print(f"    -> {len(atk_pcap_lines)} pcaps de ataque, {len(leg_lines)} líneas legítimas con evento.")

        for track in ['IPS', 'APP']:
            print(f"\n{'=' * 50}\nOptimizando {engine} - Track: {track}\n{'=' * 50}")

            for scenario in [1, 2, 3, 4, 5]:
                print(f"\n  >> Evaluando Severidad Base >= {scenario}")
                out_dir = os.path.join(master_out_dir, engine, track, f"Sev_{scenario}")
                os.makedirs(out_dir, exist_ok=True)

                (atk_data_pcap, atk_data_flow, leg_data_flow,
                 atk_alert_counts, leg_alert_counts,
                 atk_diff_counts, leg_diff_counts,
                 atk_line_co_occur, leg_line_co_occur) = build_scenario_structures(
                    atk_pcap_lines, leg_lines, scenario, track)

                sids_ataque = set(atk_alert_counts.keys())
                sids_legitimo = set(leg_alert_counts.keys())
                sids_activos = sids_ataque.union(sids_legitimo)

                if not sids_activos:
                    print("      -> Skip: sin IDs activos en este escenario.")
                    continue

                sids_pre500 = {s for s in sids_activos if leg_diff_counts[s] <= 500}
                removed_pre500 = sids_activos - sids_pre500
                export_removed_ids(os.path.join(out_dir, "1a_PreCons_Pruning500_Removed.csv"), removed_pre500)

                sids_pre1000 = {s for s in sids_activos if leg_diff_counts[s] <= 1000}
                removed_pre1000 = sids_activos - sids_pre1000
                export_removed_ids(os.path.join(out_dir, "1b_PreCons_Pruning1000_Removed.csv"), removed_pre1000)

                ids_fp_exclusivos = sids_legitimo - sids_ataque
                sids_cons = sids_activos - ids_fp_exclusivos
                export_removed_ids(os.path.join(out_dir, "1c_Phase1_Exclusive_FP_Removed.csv"), ids_fp_exclusivos)

                sids_post500 = {s for s in sids_cons if leg_diff_counts[s] <= 500}
                removed_post500_total = ids_fp_exclusivos | (sids_cons - sids_post500)
                export_removed_ids(os.path.join(out_dir, "1c_PostCons_Pruning500_Removed.csv"), removed_post500_total)

                sids_post1000 = {s for s in sids_cons if leg_diff_counts[s] <= 1000}
                removed_post1000_total = ids_fp_exclusivos | (sids_cons - sids_post1000)
                export_removed_ids(os.path.join(out_dir, "1d_PostCons_Pruning1000_Removed.csv"), removed_post1000_total)

                mixed_sids = [i for i in sids_cons if i in sids_ataque and i in sids_legitimo]
                candidate_sids = sorted(mixed_sids, key=lambda i: leg_diff_counts[i], reverse=True)

                history = []
                current_sids = set(sids_cons)

                current_gm = calc_metrics(current_sids, atk_data_pcap, leg_data_flow, TOTAL_ATK_PCAPS,
                                          TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                          atk_diff_counts, leg_diff_counts,
                                          atk_line_co_occur, leg_line_co_occur)[6]
                iteration_count = 1

                detailed_log_path = os.path.join(out_dir, "4_Detailed_Execution_Log.txt")
                with open(detailed_log_path, 'w', encoding='utf-8') as log_f:
                    log_f.write(
                        f"=== START GM OPTIMIZATION - Engine: {engine} | Track: {track} | Sev >= {scenario} ===\n\n")
                    log_f.write("=== PHASE 1: EXCLUSIVE FP REMOVAL (CONSERVATIVE) ===\n")
                    log_f.write(f"[State after Phase 1] Active IDs: {len(sids_cons)} | GM: {current_gm:.6f}\n\n")
                    log_f.write("=== PHASE 2: DIFFERENT ALERTS/FLOW SORTED OPTIMIZATION (G-MEAN) ===\n")

                    for sid in candidate_sids:
                        if sid not in current_sids:
                            continue

                        test_ids = current_sids - {sid}
                        m_res = calc_metrics(test_ids, atk_data_pcap, leg_data_flow, TOTAL_ATK_PCAPS,
                                             TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                             atk_diff_counts, leg_diff_counts,
                                             atk_line_co_occur, leg_line_co_occur)
                        m_gm = m_res[6]

                        log_f.write(f"Iteration {iteration_count}:\n")
                        log_f.write(f"  Evaluating ID {sid} -> GM: {m_gm:.6f}\n")

                        if m_gm > current_gm:
                            current_sids.remove(sid)
                            current_gm = m_gm
                            log_f.write(f"  [+] IMPROVEMENT FOUND: Removed ID {sid}. New GM: {current_gm:.6f}\n\n")

                            history.append({
                                'Step': iteration_count, 'Removed_ID': sid,
                                'TP_PCAPs': m_res[0], 'FN_PCAPs': m_res[1], 'TN_Flows': m_res[2], 'FP_Flows': m_res[3],
                                'TPR': round(m_res[4], 6), 'TNR': round(m_res[5], 6), 'G-Mean': round(m_res[6], 6),
                                'Alerts_TP': m_res[7], 'Alerts_FP': m_res[8], 'Alerts_TP_Diff': m_res[9],
                                'Alerts_FP_Diff': m_res[10], 'Total_Alerts': m_res[7] + m_res[8]
                            })
                        else:
                            log_f.write(f"  [-] No improvement. Keeping ID {sid}.\n\n")
                        iteration_count += 1

                    removed_agresive_total = sids_activos - current_sids

                    cols = ['Step', 'Removed_ID', 'TP_PCAPs', 'FN_PCAPs', 'TN_Flows', 'FP_Flows',
                            'TPR', 'TNR', 'G-Mean', 'Alerts_TP', 'Alerts_FP', 'Alerts_TP_Diff',
                            'Alerts_FP_Diff', 'Total_Alerts']
                    if history:
                        pd.DataFrame(history).to_csv(os.path.join(out_dir, "2_GM_Optimization_Steps.csv"), index=False)
                    else:
                        pd.DataFrame(columns=cols).to_csv(os.path.join(out_dir, "2_GM_Optimization_Steps.csv"),
                                                          index=False)

                    log_f.write("=== FINAL SUMMARY ===\n")
                    log_f.write(f"Final Active IDs: {len(current_sids)}\n")
                    log_f.write(f"Final GM Optimal: {current_gm:.6f}\n")

                report_path = os.path.join(out_dir, "3_Optimization_Summary.txt")
                with open(report_path, "w", encoding="utf-8") as rf:
                    rf.write("=== G-MEAN OPTIMIZATION SUMMARY ===\n")
                    rf.write(f"Engine: {engine} | Track: {track} | Base Severity >= {scenario}\n\n")

                    report_block(rf, "PRUNING 500", sids_pre500, removed_pre500, atk_data_pcap, leg_data_flow,
                                 TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                 atk_diff_counts, leg_diff_counts, atk_line_co_occur, leg_line_co_occur)
                    report_block(rf, "PRUNING 1000", sids_pre1000, removed_pre1000, atk_data_pcap, leg_data_flow,
                                 TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                 atk_diff_counts, leg_diff_counts, atk_line_co_occur, leg_line_co_occur)
                    report_block(rf, "CONSERVATIVE PRUNING", sids_cons, ids_fp_exclusivos, atk_data_pcap, leg_data_flow,
                                 TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts, leg_alert_counts,
                                 atk_diff_counts, leg_diff_counts, atk_line_co_occur, leg_line_co_occur)
                    report_block(rf, "500+CONSERVATIVE", sids_post500, removed_post500_total, atk_data_pcap,
                                 leg_data_flow, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts,
                                 leg_alert_counts, atk_diff_counts, leg_diff_counts, atk_line_co_occur,
                                 leg_line_co_occur)
                    report_block(rf, "1000+CONSERVATIVE", sids_post1000, removed_post1000_total, atk_data_pcap,
                                 leg_data_flow, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts,
                                 leg_alert_counts, atk_diff_counts, leg_diff_counts, atk_line_co_occur,
                                 leg_line_co_occur)
                    report_block(rf, "AGRESIVE PRUNING", current_sids, removed_agresive_total, atk_data_pcap,
                                 leg_data_flow, TOTAL_ATK_PCAPS, TOTAL_LEG_FLOWS, atk_alert_counts,
                                 leg_alert_counts, atk_diff_counts, leg_diff_counts, atk_line_co_occur,
                                 leg_line_co_occur)

    print("\n✅ OPTIMIZACIÓN COMPLETADA CON ÉXITO.")


if __name__ == "__main__":
    main()