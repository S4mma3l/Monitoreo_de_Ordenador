import csv
import os
from collections import defaultdict

# --- Configuración ---
# Asegúrate de que este nombre coincida con el archivo CSV generado por el otro script
LOG_FILE_PROCESS_CSV = "monitor_seguridad_local_procesos.csv"
# ---------------------

def analizar_variaciones_proceso(csv_filepath):
    """
    Lee el archivo CSV, agrupa los procesos por nombre
    y reporta nombres que tienen variaciones en Hash, Ruta o Línea de Comandos.
    Proporciona contexto y recomendaciones para cada variación.
    """
    print(f"[*] Analizando el archivo: {csv_filepath}")

    if not os.path.exists(csv_filepath):
        print(f"[ERROR] El archivo '{csv_filepath}' no fue encontrado.")
        print("        Asegúrate de que el script de monitorización se ha ejecutado y ha generado el archivo.")
        return

    # Diccionario para almacenar las combinaciones únicas de (Hash, Ruta, Cmdline) por nombre de proceso
    # defaultdict(set) creará automáticamente un conjunto vacío para una nueva clave
    # Almacenaremos tuplas (hash, ruta, cmdline, pid_ejemplo, conexiones_ejemplo) para tener contexto
    name_to_variations = defaultdict(set)
    total_procesos_leidos = 0
    procesos_con_info_valida = 0

    try:
        with open(csv_filepath, mode='r', newline='', encoding='utf-8') as csvfile:
            # Usamos DictReader que lee el encabezado para acceder a las columnas por nombre
            reader = csv.DictReader(csvfile)

            # Verificar que las columnas necesarias existan en el encabezado
            required_columns = ['Timestamp', 'PID', 'Nombre', 'Usuario', 'Ruta Ejecutable',
                                'Línea de Comandos', 'PPID', 'Hash SHA256', 'Conexiones']
            if not all(col in reader.fieldnames for col in required_columns):
                missing = [col for col in required_columns if col not in reader.fieldnames]
                print(f"[ERROR] El archivo CSV '{csv_filepath}' no contiene todas las columnas necesarias.")
                print(f"        Columnas faltantes: {', '.join(missing)}")
                print("        Asegúrate de estar analizando el archivo CSV correcto generado por la última versión del script de monitorización.")
                return

            # Leer filas y recopilar combinaciones únicas por nombre
            for row in reader:
                total_procesos_leidos += 1
                # Usar .get() con valor por defecto None o "N/A" para manejar posibles filas incompletas
                timestamp = row.get('Timestamp', 'N/A')
                pid = row.get('PID', 'N/A')
                nombre_proceso = row.get('Nombre')
                usuario = row.get('Usuario', 'N/A')
                ruta_ejecutable = row.get('Ruta Ejecutable', 'N/A')
                linea_comandos = row.get('Línea de Comandos', 'N/A')
                ppid = row.get('PPID', 'N/A')
                hash_sha256 = row.get('Hash SHA256')
                conexiones = row.get('Conexiones', 'N/A') # Las conexiones están en una sola cadena

                # Solo procesar si tenemos al menos un nombre y un hash que no sea un error
                # Consideramos 'N/A' o que empieza con 'N/A -' como hash inválido para comparación
                if nombre_proceso and hash_sha256 and not hash_sha256.startswith("N/A"):
                    procesos_con_info_valida += 1

                    # Crear una tupla que representa una combinación única de atributos clave
                    # Incluimos PID y Conexiones de ejemplo para contexto en el reporte, aunque no comparamos POR ELLOS
                    unique_combination = (
                        hash_sha256,
                        ruta_ejecutable,
                        linea_comandos,
                        ppid, # Incluir PPID para contexto
                        conexiones, # Incluir conexiones para contexto
                        # Opcional: añadir usuario si te interesa la variación por usuario
                        # usuario
                    )
                    name_to_variations[nombre_proceso].add(unique_combination)

        print(f"[*] Lectura completa. Filas leídas: {total_procesos_leidos}, Filas con info válida (Nombre+Hash): {procesos_con_info_valida}")
        print("-" * 80)
        print(">>> Reporte de Variaciones de Procesos por Nombre <<<")
        print("-" * 80)

        # Analizar los nombres con múltiples combinaciones únicas
        nombres_con_variacion_total = 0
        for nombre, variations in sorted(name_to_variations.items()): # Ordenar por nombre para mejor lectura
            if len(variations) > 1:
                nombres_con_variacion_total += 1
                print(f"!!! VARIACIÓN DETECTADA para el proceso: '{nombre}' ({len(variations)} combinaciones únicas encontradas)")

                # Ordenar las variaciones para que el reporte sea consistente
                sorted_variations = sorted(list(variations))

                for i, var_tuple in enumerate(sorted_variations):
                    hash_val, ruta_val, cmdline_val, ppid_val, conexiones_val = var_tuple # , usuario_val si se incluyó

                    print(f"  Variación #{i + 1}:")
                    print(f"    Hash SHA256:     {hash_val}")
                    print(f"    Ruta Ejecutable: '{ruta_val}'")
                    print(f"    Línea Comandos:  '{cmdline_val}'")
                    print(f"    PPID de Ejemplo: {ppid_val}")
                    print(f"    Conexiones:      {conexiones_val}")
                    # if 'usuario_val' in locals(): print(f"    Usuario:         {usuario_val}")

                # --- Recomendaciones de Análisis para esta Variación ---
                print("\n  Recomendaciones de Análisis:")
                print("  ----------------------------")
                print(f"  1.  Investiga la 'Ruta Ejecutable': ¿Es una ubicación estándar o una carpeta temporal/de descarga/usuario inusual?")
                print(f"  2.  Verifica el 'Hash SHA256': Cópialo y búscalo en bases de datos de inteligencia de amenazas (ej. VirusTotal).")
                print(f"  3.  Analiza la 'Línea de Comandos': ¿Contiene argumentos sospechosos, codificación (Base64), o referencias a scripts/archivos inusuales?")
                print(f"  4.  Examina las 'Conexiones': ¿Son esperadas para este proceso? ¿Las IPs/puertos remotos son conocidos o sospechosos (busca en Whois/TI)?")
                print(f"  5.  Considera el PPID ({ppid_val}): ¿El proceso padre listado es típico para este proceso ({nombre})? (Requiere análisis adicional fuera de este script).")
                print(f"  6.  Busca el proceso por PID o Nombre en herramientas más avanzadas en vivo (Process Explorer, Task Manager, EDR).")
                print(f"  7.  Si es sospechoso, considera aislar la máquina para análisis forense más profundo.")
                print("-" * 40) # Separador entre reportes de nombres diferentes

        if nombres_con_variacion_total == 0:
            print("[*] No se detectaron nombres de proceso con múltiples combinaciones únicas de Hash, Ruta o Línea de Comandos en este log.")
            print("    Esto es un buen indicio, pero no excluye otras técnicas de ataque (ej. inyección de procesos, malware con nombres únicos).")

        print("-" * 80)
        print(f">>> Análisis Finalizado. Nombres con variaciones detectadas: {nombres_con_variacion_total}")


    except FileNotFoundError:
        # Esto debería ser capturado por la verificación inicial, pero es una buena práctica tenerlo
        print(f"[ERROR] El archivo '{csv_filepath}' no fue encontrado durante la lectura (segunda verificación).")
    except Exception as e:
        print(f"[ERROR] Ocurrió un error crítico al leer o procesar el archivo CSV: {e}")

# --- Ejecutar el análisis ---
if __name__ == "__main__":
    analizar_variaciones_proceso(LOG_FILE_PROCESS_CSV)