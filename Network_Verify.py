import csv
import os
from collections import defaultdict
import ipaddress # Para analizar IPs fácilmente

# --- Configuración ---
# Asegúrate de que este nombre coincida con el archivo CSV generado por el monitor de conexiones
LOG_FILE_CONNECTIONS_CSV = "network_connection_events.csv"

# Definir rangos de IP internos para distinguirlos de externos
# Añade aquí los rangos de red interna de tu empresa en formato CIDR
# Ejemplos: "192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"
INTERNAL_IP_RANGES_CIDR = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.0/8" # Loopback es interno
    # Agrega aquí tus rangos específicos
]

# Umbral para considerar algo "poco común" (ej. apareció N veces o menos)
LOW_OCCURRENCE_THRESHOLD = 3
# ---------------------

# Rutas de ejemplo consideradas potencialmente sospechosas (las mismas que en el analizador de hashes)
# Añade aquí rutas relevantes para tu entorno si es necesario
SUSPICIOUS_PATHS_FRAGMENT = [
    "\\temp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "/tmp/",
    "/var/tmp/",
    # Puedes añadir fragmentos de rutas o nombres de carpetas sospechosas aquí
]

def is_internal_ip(ip_str):
    """Verifica si una dirección IP es interna basándose en los rangos configurados."""
    if ip_str in ['N/A', '', None]:
        return False # Las direcciones no disponibles no son internas

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for network_cidr in INTERNAL_IP_RANGES_CIDR:
            network_obj = ipaddress.ip_network(network_cidr, strict=False) # strict=False permite host addresses
            if ip_obj in network_obj:
                return True
        return False
    except ValueError:
        # No es una IP válida
        return False
    except Exception as e:
        print(f"[ERROR] Error al verificar IP interna {ip_str}: {e}")
        return False

def contains_suspicious_path_fragment(path):
    """Verifica si la ruta contiene algún fragmento sospechoso."""
    if not path or path == 'N/A':
        return False
    path_lower = path.lower()
    for fragment in SUSPICIOUS_PATHS_FRAGMENT:
        if fragment.lower() in path_lower:
            return True
    return False


def analyze_network_events(csv_filepath):
    """
    Analiza el archivo CSV de eventos de conexión para identificar patrones y anomalías.
    """
    print(f"[*] Iniciando análisis de eventos de conexión desde: {csv_filepath}")

    if not os.path.exists(csv_filepath):
        print(f"[ERROR] El archivo '{csv_filepath}' no fue encontrado.")
        print("        Asegúrate de que el script de monitorización de conexiones se ha ejecutado y ha generado el archivo.")
        return

    # --- Estructuras para agregación y análisis ---
    total_events = 0
    opened_events = 0
    closed_events = 0

    # Contadores de frecuencia
    process_event_counts = defaultdict(int) # Nombre del proceso -> count total
    remote_ip_counts = defaultdict(int)     # IP remota -> count total
    remote_endpoint_counts = defaultdict(int) # IP remota:Puerto remota -> count total
    local_endpoint_counts = defaultdict(int)  # IP local:Puerto local -> count total (útil para puertos source)

    # Para identificar elementos únicos o de baja ocurrencia
    unique_remote_ips = set()
    unique_remote_endpoints = set()
    unique_processes = set() # Nombre del proceso
    unique_process_paths = set() # Ruta del ejecutable

    # Para analizar conexiones en escucha (LISTEN)
    listening_endpoints = {} # (IP:Puerto Local) -> { 'pid': ..., 'name': ..., 'path': ..., 'user': ... }

    # Para rastrear actividad interna vs externa
    internal_connections_opened = 0
    external_connections_opened = 0

    # Para identificar procesos con rutas sospechosas que hicieron conexiones
    suspicious_path_processes_with_connections = set() # Conjunto de (Nombre, Ruta, Cmdline, PID ejemplo, Usuario ejemplo)


    # --- Lectura y agregación de datos ---
    print("[*] Leyendo y agregando datos del CSV...")
    try:
        with open(csv_filepath, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)

            # Verificar columnas requeridas (mínimo para este análisis)
            required_cols_analysis = ['EventType', 'PID', 'ProcessName', 'ProcessPath',
                                      'ProcessCmdline', 'LocalAddress', 'RemoteAddress',
                                      'Status', 'Protocol', 'EventDetails']

            if not all(col in reader.fieldnames for col in required_cols_analysis):
                 missing = [col for col in required_cols_analysis if col not in reader.fieldnames]
                 print(f"[ERROR] El archivo CSV '{csv_filepath}' le faltan columnas para el análisis ({', '.join(missing)}).")
                 print("        Asegúrate de usar un archivo generado por la última versión del monitor.")
                 # Opcional: imprimir encabezados encontrados para depurar
                 # print(f"        Encabezados encontrados: {reader.fieldnames}")
                 return


            for row in reader:
                total_events += 1

                # Usar .get() con valor por defecto para manejar posibles filas incompletas
                event_type = row.get('EventType')
                pid = row.get('PID', 'N/A')
                p_name = row.get('ProcessName', 'N/A')
                p_path = row.get('ProcessPath', 'N/A')
                p_cmdline = row.get('ProcessCmdline', 'N/A')
                l_addr_str = row.get('LocalAddress', 'N/A')
                r_addr_str = row.get('RemoteAddress', 'N/A')
                status = row.get('Status', 'N/A')
                # protocol = row.get('Protocol', 'N/A') # Protocolo no usado directamente en agregaciones principales, pero está en el CSV
                event_details_str = row.get('EventDetails', '') # Contiene User='...'

                # Extraer usuario de EventDetails
                user = "N/A"
                if event_details_str:
                    # Intentar parsear el usuario que está en formato User='nombre'
                    user_match = [part for part in event_details_str.split(',') if "User='" in part]
                    if user_match:
                        try:
                            user = user_match[0].split("User='", 1)[1].split("'", 1)[0]
                        except IndexError:
                             user = "Parse Error" # Si el formato no es el esperado

                # --- Agregación de datos ---
                if event_type == 'ConnectionOpened':
                    opened_events += 1
                    # Solo contabilizar conexiones salientes/entrantes activas para análisis de actividad (no LISTEN)
                    if status != 'LISTEN' and p_name and p_name != 'Info no disponible': # Asegurarse de que es un proceso conocido y no LISTEN
                        process_event_counts[p_name] += 1
                        unique_processes.add(p_name)
                        if p_path and p_path != 'Info no disponible':
                            unique_process_paths.add(p_path)

                        # Contabilizar endpoints remotos si están disponibles y válidos
                        if r_addr_str and r_addr_str != 'N/A':
                            # Asegurarse de que el formato es IP:Puerto antes de dividir
                            if ':' in r_addr_str:
                                r_ip = r_addr_str.rsplit(':', 1)[0] # Usar rsplit para IPv6
                                # r_port = r_addr_str.rsplit(':', 1)[1] # Puerto no usado en conteo IP
                                remote_ip_counts[r_ip] += 1
                                remote_endpoint_counts[r_addr_str] += 1
                                unique_remote_ips.add(r_ip)
                                unique_remote_endpoints.add(r_addr_str)

                                # Clasificar conexión como interna o externa (solo si está "abierta" y no es LISTEN)
                                if is_internal_ip(r_ip):
                                    internal_connections_opened += 1
                                else:
                                    external_connections_opened += 1
                            else:
                                # Dirección remota no tiene formato IP:Puerto esperado, registrar o ignorar
                                # print(f"[DEBUG] RemoteAddress sin puerto o mal formado: {r_addr_str}") # Debug si quieres ver estos casos
                                pass # Ignorar en el conteo de endpoints remotos


                        # Contabilizar endpoints locales si están disponibles (útil para ver puertos source)
                        if l_addr_str and l_addr_str != 'N/A':
                            local_endpoint_counts[l_addr_str] += 1 # Contamos el endpoint local completo


                elif event_type == 'ConnectionClosed':
                    closed_events += 1
                    # Podrías también contabilizar cierres por proceso/IP si es relevante para tu análisis


                # --- Identificar puertos en escucha (LISTEN) y el proceso ---
                # Solo procesar filas donde el estado sea LISTEN
                if status == 'LISTEN':
                    if l_addr_str and l_addr_str != 'N/A':
                        # Guardamos info del proceso para este endpoint en escucha
                        # Si ya existe una entrada, no la sobrescribimos a menos que la info sea más completa
                        # (Ej. una entrada anterior tenía 'Info no disponible' y ahora tenemos los detalles)
                        current_listen_info = {
                             'pid': pid,
                             'name': p_name,
                             'path': p_path,
                             'user': user,
                             # 'protocol': protocol, # Protocolo ya está en el endpoint str si el formato es IP:Puerto
                             'cmdline': p_cmdline
                         }
                        # Sobrescribir si no existe o si la entrada existente tiene info incompleta
                        if l_addr_str not in listening_endpoints or listening_endpoints[l_addr_str].get('name') == 'Info no disponible':
                              listening_endpoints[l_addr_str] = current_listen_info
                        # Opcional: Si quieres registrar *todas* las veces que un endpoint aparece en LISTEN,
                        # podrías cambiar listening_endpoints a defaultdict(list) y añadir la info.
                        # La implementación actual solo guarda la última info de proceso vista para ese endpoint LISTEN.


                # --- Identificar procesos con rutas sospechosas que hicieron conexiones ---
                # Solo si el evento es "Opened" y no es un estado de LISTEN, y si tenemos info del proceso y ruta VÁLIDA
                if event_type == 'ConnectionOpened' and status != 'LISTEN' and \
                   p_name != 'Info no disponible' and p_path and p_path != 'N/A' and p_path != 'Info no disponible':

                    if contains_suspicious_path_fragment(p_path):
                         # Almacenar una tupla que identifique la combinación única sospechosa
                         # Usamos PID y Usuario como ejemplo, no para comparar por ellos, sino para contexto
                         suspicious_path_processes_with_connections.add((p_name, p_path, p_cmdline, pid, user))


    except FileNotFoundError:
         print(f"[ERROR] El archivo '{csv_filepath}' no fue encontrado durante la lectura (segunda verificación).")
         return
    except Exception as e:
        print(f"[ERROR] Ocurrió un error crítico al leer o procesar el archivo CSV: {e}")
        # Opcional: imprimir la fila que causó el error si es posible
        # if 'row' in locals(): print(f"  Fila defectuosa: {row}")
        return

    # --- Realizar Análisis y Reportar Resultados ---
    print("\n" + "="*80)
    print(">>> REPORTE DE ANÁLISIS DE EVENTOS DE CONEXIÓN <<<")
    print("="*80)

    print("\n--- 1. Resumen General ---")
    print(f"  Archivo Analizado: {csv_filepath}")
    print(f"  Total Eventos Leídos: {total_events}")
    print(f"  Eventos de Conexión Abierta: {opened_events}")
    print(f"  Eventos de Conexión Cerrada: {closed_events}")
    print(f"  Procesos Únicos con Actividad de Conexión (por nombre): {len(unique_processes)}")
    print(f"  Rutas de Ejecutables Únicas con Actividad: {len(unique_process_paths)}")
    print(f"  IPs Remotas Únicas Contactadas: {len(unique_remote_ips)}")
    print(f"  Endpoints Remotos Únicos (IP:Puerto): {len(unique_remote_endpoints)}")
    print(f"  Endpoints Locales Únicos Vistos: {len(local_endpoint_counts)}")


    print("\n--- 2. Clasificación de Conexiones Abiertas (por IP Remota) ---")
    # Recalcular total_opened_excluding_listen basándose en los conteos, que ya excluyen LISTEN y 'Info no disponible'
    total_opened_excluding_listen_counted = sum(process_event_counts.values()) # Suma de eventos por proceso que no son LISTEN
    print(f"  Total Conexiones Abiertas (excluyendo LISTEN y procesos 'Info no disponible'): {total_opened_excluding_listen_counted}")
    if total_opened_excluding_listen_counted > 0:
        print(f"  Conexiones a IPs Internas: {internal_connections_opened} ({internal_connections_opened/total_opened_excluding_listen_counted*100:.1f}%)")
        print(f"  Conexiones a IPs Externas: {external_connections_opened} ({external_connections_opened/total_opened_excluding_listen_counted*100:.1f}%)")
    else:
        print("  No hay suficientes datos de conexiones abiertas válidas para clasificar.")

    if not INTERNAL_IP_RANGES_CIDR:
         print("  [AVISO] No se configuraron rangos de IP internos. Toda IP se considera externa.")


    print("\n--- 3. Principales Generadores de Eventos de Conexión (Top 10 Procesos por conteo) ---")
    # Ordenar procesos por conteo descendente
    sorted_processes = sorted(process_event_counts.items(), key=lambda item: item[1], reverse=True)
    if sorted_processes:
        for i, (process_name, count) in enumerate(sorted_processes[:10]):
            print(f"  {i + 1}. '{process_name}': {count} eventos")
    else:
        print("  No hay datos de conteo de eventos por proceso.")

    print("\n--- 4. Destinos Remotos Más Frecuentes (Top 10 IP:Puerto por conteo) ---")
    sorted_remote_endpoints = sorted(remote_endpoint_counts.items(), key=lambda item: item[1], reverse=True)
    if sorted_remote_endpoints:
        for i, (endpoint, count) in enumerate(sorted_remote_endpoints[:10]):
            print(f"  {i + 1}. '{endpoint}': {count} eventos")
    else:
         print("  No hay datos de conteo por endpoint remoto.")

    print("\n--- 5. Elementos Poco Comunes (Potencialmente Sospechosos) ---")
    print(f"  (Elementos que aparecieron {LOW_OCCURRENCE_THRESHOLD} veces o menos en eventos de conexión abierta, excluyendo LISTEN y 'Info no disponible')")

    low_occurrence_ips = [(ip, count) for ip, count in remote_ip_counts.items() if count <= LOW_OCCURRENCE_THRESHOLD]
    low_occurrence_endpoints = [(ep, count) for ep, count in remote_endpoint_counts.items() if count <= LOW_OCCURRENCE_THRESHOLD]
    low_occurrence_processes = [(p, count) for p, count in process_event_counts.items() if count <= LOW_OCCURRENCE_THRESHOLD]

    print(f"  IPs Remotas Poco Comunes ({len(low_occurrence_ips)} encontradas):")
    if low_occurrence_ips:
        for ip, count in sorted(low_occurrence_ips, key=lambda item: item[1]): # Ordenar por conteo ascendente
            print(f"    - {ip} ({count} veces)")
    else:
        print("    Ninguna IP remota apareció tan pocas veces.")

    print(f"\n  Endpoints Remotos Poco Comunes (IP:Puerto) ({len(low_occurrence_endpoints)} encontrados):")
    if low_occurrence_endpoints:
        for ep, count in sorted(low_occurrence_endpoints, key=lambda item: item[1]): # Ordenar por conteo ascendente
            print(f"    - {ep} ({count} veces)")
    else:
        print("    Ningún endpoint remoto apareció tan pocas veces.")

    print(f"\n  Procesos Poco Comunes ({len(low_occurrence_processes)} encontrados):")
    if low_occurrence_processes:
        for process_name, count in sorted(low_occurrence_processes, key=lambda item: item[1]): # Ordenar por conteo ascendente
            print(f"    - '{process_name}' ({count} eventos)")
    else:
        print("    Ningún proceso generó tan pocos eventos de conexión.")


    print("\n--- 6. Puertos Locales en Escucha (Estado LISTEN) ---")
    if listening_endpoints:
        print(f"  Endpoints locales en estado LISTEN ({len(listening_endpoints)} encontrados):")
        # --- FIX para el error ValueError ---
        # Ordenar por puerto local. Manejar casos sin ':' o puerto vacío/no numérico.
        def get_port_for_sorting(endpoint_str):
            if ':' in endpoint_str:
                parts = endpoint_str.rsplit(':', 1) # Usar rsplit para IPv6
                if len(parts) > 1 and parts[1].isdigit(): # Verificar que hay algo después de ':' y es un dígito
                    return int(parts[1])
            return 0 # Valor por defecto si no tiene puerto o el formato es inválido

        sorted_listeners = sorted(listening_endpoints.items(), key=lambda item: get_port_for_sorting(item[0]))
        # --- Fin FIX ---

        for endpoint, info in sorted_listeners:
            print(f"  - {endpoint} ({info.get('protocol', 'N/A')})")
            print(f"    PID: {info.get('pid', 'N/A')}, Nombre: '{info.get('name', 'N/A')}', Usuario: '{info.get('user', 'N/A')}'")
            print(f"    Ruta: '{info.get('path', 'N/A')}'")
            print(f"    Cmdline: '{info.get('cmdline', 'N/A')}'")
            print("-" * 20)
    else:
        print("  No se detectaron puertos locales en estado LISTEN en el log.")

    print("\n--- 7. Procesos con Rutas Potencialmente Sospechosas que Hicieron Conexiones ---")
    print(f"  (Procesos cuya ruta contiene fragmentos de: {', '.join(SUSPICIOUS_PATHS_FRAGMENT)})")
    if suspicious_path_processes_with_connections:
        print(f"  Procesos detectados ({len(suspicious_path_processes_with_connections)} combinaciones únicas):")
        # Convertir a lista y ordenar para un output consistente
        # La tupla es (name, path, cmdline, pid_ejemplo, user_ejemplo)
        sorted_suspicious = sorted(list(suspicious_path_processes_with_connections))
        for name, path, cmdline, pid_ejemplo, user_ejemplo in sorted_suspicious:
            print(f"  - Nombre: '{name}', PID Ejemplo: {pid_ejemplo}, Usuario: '{user_ejemplo}'")
            print(f"    Ruta: '{path}'")
            print(f"    Cmdline: '{cmdline}'")
            print("    [NOTA] Este proceso hizo conexiones y su ruta es sospechosa.")
            print("-" * 20)
    else:
        print("  No se detectaron procesos con rutas sospechosas que hicieran conexiones.")


    print("\n" + "="*80)
    print(">>> RECOMENDACIONES DE ANÁLISIS <<<")
    print("="*80)
    print("Basado en este análisis del log de eventos de conexión de UNA máquina:")
    print("\n1.  Investiga todos los elementos listados en la sección 'Elementos Poco Comunes'.")
    print("    Las IPs/Endpoints remotos que aparecen pocas veces podrían ser C2s, sondas o destinos de exfiltración.")
    print("    Los procesos que aparecen pocas veces podrían ser herramientas de atacante o malware transitorio.")
    print("    Busca las IPs/Endpoints y los Hashes (usando el otro script) en fuentes de Inteligencia de Amenazas (VirusTotal, AbuseIPDB, etc.).")
    print("\n2.  Revisa todos los 'Puertos Locales en Escucha' listados.")
    print("    ¿Son puertos estándar esperados para el software instalado en esa máquina (ej. 80/443 para web server, 3389 para RDP, etc.)?")
    print("    ¿El proceso que está escuchando es el legítimo (verifica nombre, ruta, hash)?")
    print("    Puertos altos inesperados o puertos bajos no autorizados son muy sospechosos.")
    print("\n3.  Examina los 'Procesos con Rutas Potencialmente Sospechosas'.")
    print("    Incluso si el nombre es legítimo, si se ejecuta desde una carpeta temporal, de usuario, o descarga y hace conexiones, es muy sospechoso.")
    print("    Usa el analizador de hashes para verificar el hash de estos ejecutables.")
    print("\n4.  Analiza los 'Destinos Remotos Más Frecuentes' (Top 10).")
    print("    Aunque sean los más comunes, ¿son esperados? ¿Hay algún destino inusual en la lista a pesar de ser frecuente?")
    print("\n5.  Considera la proporción 'Conexiones a IPs Internas vs. Externas'.")
    print("    Una alta proporción de conexiones externas inesperadas podría indicar C2 o exfiltración.")
    print("\n6.  Cruza este log con el log de análisis de hashes ('monitor_seguridad_local_procesos.csv').")
    print("    Si un proceso con variación de hash o una ruta sospechosa (del análisis de hashes) también aparece en este log haciendo conexiones inusuales, es una fuerte correlación.")
    print("\n7.  Recuerda que estos datos son de UNA máquina.")
    print("    Para un panorama de red completo, necesitarías implementar esta monitorización en múltiples máquinas y agregar los logs en un SIEM.")
    print("\n8.  Este análisis es estático. Si detectas algo, investiga la máquina en VIVO con herramientas como Process Explorer, analizadores de red (WireShark), etc.")

    print("\n" + "="*80)
    print(">>> Fin del Reporte de Análisis <<<")
    print("="*80)


# --- Ejecutar el análisis ---
if __name__ == "__main__":
    analyze_network_events(LOG_FILE_CONNECTIONS_CSV)