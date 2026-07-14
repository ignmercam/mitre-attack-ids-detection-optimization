import os


def fusion_clasica():
    print("=== SISTEMA MAESTRO DE FUSIÓN DE LOGS (ATAQUES Y LEGÍTIMO) ===")

    # 1. Definición estricta de las combinaciones solicitadas
    rs_logic = {
        "RS3": ["Registered", "ETOpen"],
        "RS6": ["RegisteredCD", "ETOpenCD"],
        "RS8": ["Registered", "ETOpen", "QUICK"],
        "RS9": ["RegisteredCD", "ETOpenCD", "QUICK"]
    }

    # 2. Los dos tipos de tráfico (subcarpetas que hay dentro de cada paquete)
    tipos_trafico = ["AtaquesICS", "LegitimoICS"]

    # 3. Proceso principal de fusión
    for rs_name, folders in rs_logic.items():
        print(f"\n[*] Procesando {rs_name} (Carpetas: {', '.join(folders)})...")

        for t_type in tipos_trafico:
            output_dir = os.path.join(rs_name, t_type)
            os.makedirs(output_dir, exist_ok=True)

            # PASO A: Recopilar todos los nombres de PCAP únicos de esta categoría (Ataque o Legítimo)
            pcap_ids = set()
            for folder in folders:
                input_folder = os.path.join(folder, t_type)
                if os.path.exists(input_folder):
                    for f in os.listdir(input_folder):
                        if f.endswith(".log") or f.endswith(".txt"):
                            # Limpiar el nombre base
                            base = f
                            for suffix in [f"-{folder}", "-Community", "-Registered", "-RegisteredCD", "-ETOpen",
                                           "-ETOpenCD", "-QUICK"]:
                                base = base.replace(suffix, "")
                            base = base.replace(".log", "").replace(".txt", "")
                            pcap_ids.add(base)

            pcap_ids = sorted(list(pcap_ids))

            if not pcap_ids:
                print(f"  -> {t_type}: No se encontraron logs para fusionar.")
                continue

            print(f"  -> {t_type}: Encontrados {len(pcap_ids)} archivos base. Fusionando...")

            # PASO B: Fusionar los archivos encontrados
            for pcap_id in pcap_ids:
                output_file = os.path.join(output_dir, f"{pcap_id}.log")

                with open(output_file, "w", encoding="utf-8") as outfile:
                    for folder in folders:
                        input_folder = os.path.join(folder, t_type)

                        # Buscar el archivo correspondiente con extensión .log o .txt
                        file_to_read = None
                        for ext in [".log", ".txt"]:
                            path_cand_1 = os.path.join(input_folder, f"{pcap_id}-{folder}{ext}")
                            path_cand_2 = os.path.join(input_folder, f"{pcap_id}{ext}")

                            if os.path.exists(path_cand_1):
                                file_to_read = path_cand_1
                                break
                            elif os.path.exists(path_cand_2):
                                file_to_read = path_cand_2
                                break

                        if file_to_read:
                            # Marcador de inicio de bloque visual
                            outfile.write(f"{'=' * 60}\n")
                            outfile.write(f"### INICIO BLOQUE: {folder} -> {os.path.basename(file_to_read)}\n")
                            outfile.write(f"{'=' * 60}\n\n")

                            # Volcar contenido en crudo (Fusión Clásica)
                            with open(file_to_read, "r", encoding="utf-8", errors='ignore') as infile:
                                outfile.write(infile.read())

                            # Marcador de fin de bloque
                            outfile.write(f"\n\n{'=' * 60}\n")
                            outfile.write(f"### FIN BLOQUE: {folder}\n")
                            outfile.write(f"{'=' * 60}\n\n")

    print("\n✅ ¡Fusión clásica completada con éxito para Ataques y Legítimo!")


if __name__ == '__main__':
    fusion_clasica()