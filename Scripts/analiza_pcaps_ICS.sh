#!/bin/bash

# === 1. CONFIGURACIÓN DE RUTAS ICS ===
DIR_ATAQUES="/mnt/hgfs/AtaquesICS"
DIR_LEGITIMO="/mnt/hgfs/LegitimoICS"
LOGS_BASE="./logs_ics"
DIR_TEMP="./tmp_snort_running_ics"

# Mapeo de los 5 casos de estudio para ICS
ALL_CONFS=(
    "/etc/snort/snort_QUICK.conf"
    "/etc/snort/snort_Registered.conf"
    "/etc/snort/snort_RegisteredCD.conf"
    "/etc/snort/snort_ETOpen.conf"
    "/etc/snort/snort_ETOpenCD.conf"
)

ALL_LABELS=(
    "QUICK"
    "Registered"
    "RegisteredCD"
    "ETOpen"
    "ETOpenCD"
)

# === 2. MANTENER SUDO VIVO (Heartbeat) ===
# Solicita la contraseña una vez y mantiene la sesión activa indefinidamente
sudo -v
while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &

echo "======================================================"
echo "      ANALIZADOR MAESTRO ICS (ENTORNO INDUSTRIAL)     "
echo "======================================================"

# --- SELECCIÓN DE PAQUETE DE REGLAS ---
echo -e "\n[?] ¿Qué paquetes de reglas desea procesar?"
echo "1) Solo QUICK (Quickdraw)"
echo "2) Solo Registered (Standard)"
echo "3) Solo Registered (CD)"
echo "4) Solo ETOpen"
echo "5) Solo ETOpen (CD)"
echo "6) TODOS LOS PAQUETES (BARRIDO TOTAL)"
read -p "Seleccione una opción [1-6]: " opt_pkg

case $opt_pkg in
    1) PKG_INDEXES=(0) ;;
    2) PKG_INDEXES=(1) ;;
    3) PKG_INDEXES=(2) ;;
    4) PKG_INDEXES=(3) ;;
    5) PKG_INDEXES=(4) ;;
    6) PKG_INDEXES=(0 1 2 3 4) ;;
    *) echo "Opción inválida"; exit 1 ;;
esac

# --- SELECCIÓN DE FUENTE DE TRÁFICO ---
echo -e "\n[?] ¿Qué fuente de tráfico desea barrer?"
echo "1) Solo Ataques ICS"
echo "2) Solo Tráfico Legítimo ICS"
echo "3) AMBAS FUENTES"
read -p "Seleccione una opción [1-3]: " opt_trf

case $opt_trf in
    1) FUENTES=("AtaquesICS") ;;
    2) FUENTES=("LegitimoICS") ;;
    3) FUENTES=("AtaquesICS" "LegitimoICS") ;;
    *) echo "Opción inválida"; exit 1 ;;
esac

# Crear directorios base con sudo para asegurar permisos
sudo mkdir -p "$LOGS_BASE"
sudo mkdir -p "$DIR_TEMP"

# === 3. BUCLE DE PROCESAMIENTO ===
for idx in "${PKG_INDEXES[@]}"; do
    CONF="${ALL_CONFS[$idx]}"
    LABEL="${ALL_LABELS[$idx]}"
    
    echo -e "\n[>>>] MOTOR ACTUAL: $LABEL"

    for FUENTE in "${FUENTES[@]}"; do
        PCAP_PATH="$([ "$FUENTE" == "AtaquesICS" ] && echo "$DIR_ATAQUES" || echo "$DIR_LEGITIMO")"
        DESTINO="$LOGS_BASE/$LABEL/$FUENTE"
        
        sudo mkdir -p "$DESTINO"
        echo "    [+] Fuente: $FUENTE -> $DESTINO"

        for IFILE in "$PCAP_PATH"/*.{pcap,pcapng}; do
            [ -e "$IFILE" ] || continue
            
            FILENAME=$(basename "$IFILE")
            NAME_NO_EXT="${FILENAME%.*}"
            LOG_FILE="$DESTINO/${NAME_NO_EXT}-${LABEL}.log"

            echo -n "        -> $FILENAME ... "

            # Limpieza del área de trabajo temporal
            sudo rm -rf "$DIR_TEMP"/*
            
            # --- EJECUCIÓN DE SNORT ---
            # -k none: ignora checksums inválidos para no perder paquetes
            # -y -U: Formato de timestamp completo para los logs
            sudo snort -c "$CONF" -r "$IFILE" -A fast -N -l "$DIR_TEMP" -y -U -k none > /dev/null 2>&1
            
            # --- GESTIÓN DE RESULTADOS ---
            RESULTADO=$(sudo find "$DIR_TEMP" -name "alert*" -type f | head -n 1)

            if [ -n "$RESULTADO" ]; then
                sudo mv "$RESULTADO" "$LOG_FILE"
                sudo chown $USER:$USER "$LOG_FILE"
                NUM=$(wc -l < "$LOG_FILE")
                echo "✅ OK ($NUM alertas)"
            else
                # Registro de análisis sin alertas
                sudo touch "$LOG_FILE"
                sudo chown $USER:$USER "$LOG_FILE"
                echo "⚠️  0 alertas"
            fi

            sudo rm -rf "$DIR_TEMP"/*
        done
    done
done

# Limpieza final
sudo rm -rf "$DIR_TEMP"
echo -e "\n======================================================"
echo "ANÁLISIS ICS FINALIZADO."
echo "Estructura generada en: $LOGS_BASE"
echo "======================================================"
