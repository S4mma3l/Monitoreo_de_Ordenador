import time
import subprocess
import platform
import psutil
import os
from datetime import datetime
import csv
# import hashlib # No necesitamos hash en este script de monitoreo de conexiones

# --- Configuración ---
INTERVALO_SEGUNDOS = 10 # Monitorear cada 10 segundos es más útil para conexiones
LOG_FILE_GENERAL = "network_monitor_general.log"
LOG_FILE_CONNECTIONS_CSV = "network_connection_events.csv" # CSV para eventos de conexión
# ---------------------

# Estado global para rastrear las conexiones del ciclo anterior
# Usaremos un conjunto de tuplas para identificar conexiones únicas de forma eficiente
# Tupla: (laddr_ip, laddr_port, raddr_ip, raddr_port, status, pid)
previous_connections_set = set()
# También almacenaremos info básica de procesos del ciclo anterior para procesos que podrían terminar
# Esto ayuda a reportar el nombre/ruta para conexiones que se cierran.
# Diccionario: { pid: { 'name': ..., 'path': ..., 'cmdline': ... } }
last_known_process_info = {}


def log_event(message, level="INFO"):
    """Escribe un mensaje con timestamp y nivel al archivo de log general."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} [{level}] {message}"
    print(log_entry) # También imprimir en consola
    try:
        with open(LOG_FILE_GENERAL, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"ERROR: No se pudo escribir en el archivo de log general {LOG_FILE_GENERAL}: {e}")

def write_connection_event_csv(event_data):
    """Escribe un evento de conexión en el archivo CSV."""
    # Encabezados para el CSV de eventos de conexión
    csv_headers = [
        'Timestamp', 'EventType', 'PID', 'ProcessName', 'ProcessPath',
        'ProcessCmdline', 'LocalAddress', 'RemoteAddress', 'Status', 'Protocol',
        'EventDetails' # Cualquier detalle adicional (ej. error)
    ]

    # Determinar si necesitamos escribir los encabezados (si el archivo es nuevo)
    csv_mode = 'a' # Modo append por defecto
    if not os.path.exists(LOG_FILE_CONNECTIONS_CSV):
         csv_mode = 'w' # Modo write si es la primera vez
         # Abrir y escribir encabezados INMEDIATAMENTE si es modo 'w'
         with open(LOG_FILE_CONNECTIONS_CSV, mode='w', newline='', encoding='utf-8') as csvfile:
              csv_writer = csv.writer(csvfile)
              csv_writer.writerow(csv_headers)
         log_event(f"Archivo CSV de eventos de conexión creado: {LOG_FILE_CONNECTIONS_CSV}", "INFO")


    try:
        with open(LOG_FILE_CONNECTIONS_CSV, mode='a', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # event_data debe ser una lista que coincida con los encabezados
            csv_writer.writerow(event_data)

    except Exception as e:
        log_event(f"ERROR: No se pudo escribir evento de conexión en {LOG_FILE_CONNECTIONS_CSV}: {e}", "ERROR")


def get_process_info_map():
    """
    Crea un diccionario mapeando PID a información relevante del proceso.
    Maneja errores de acceso.
    """
    pid_info = {}
    global last_known_process_info # Vamos a actualizar el estado global
    current_pids_with_info = set() # Para saber qué PIDs procesamos exitosamente en este ciclo

    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            name = pinfo.get('name', 'N/A')
            exe_path = pinfo.get('exe', 'N/A')
            cmdline_list = pinfo.get('cmdline')
            cmdline = " ".join(cmdline_list) if cmdline_list else ""

            pid_info[pid] = {
                'name': name,
                'path': exe_path,
                'cmdline': cmdline,
                'username': pinfo.get('username', 'N/A') or 'N/A'
            }
            current_pids_with_info.add(pid)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            # Ignorar procesos que desaparecen, son zombies o no accesibles.
            pass
        except Exception as e:
            log_event(f"Error inesperado al obtener info del proceso {proc.pid}: {e}", "ERROR")

    # Opcional: Actualizar last_known_process_info con la información de este ciclo
    # Esto es útil si quieres la última info conocida para procesos que cierran conexiones y luego terminan
    # Sin embargo, esto puede consumir mucha memoria si hay muchos procesos únicos a lo largo del tiempo.
    # Para simplicidad inicial, dependemos de pid_info del ciclo actual. Si el proceso cierra la conexión Y termina
    # en el mismo intervalo, su info podría no estar en pid_info.

    # Una alternativa más segura para procesos cerrados es simplemente usar el PID
    # y si la info no está en pid_info, registrar "Info no disponible".
    # Mantendremos la dependencia de pid_info del ciclo actual por ahora.
    # Puedes decidir si quieres persistir last_known_process_info de forma más robusta (guardar a archivo).

    return pid_info


def monitor_network_connections():
    """
    Monitorea conexiones de red, detecta eventos de apertura/cierre
    y los registra con info del proceso.
    """
    global previous_connections_set # Vamos a modificar el estado global

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_event(f"\n--- Iniciando escaneo de conexiones [{timestamp}] ---")

    # 1. Obtener el mapa actual de PID a información de proceso
    pid_info_map = get_process_info_map()
    log_event(f"Info de {len(pid_info_map)} procesos obtenida.", "DEBUG")


    # 2. Obtener el conjunto actual de conexiones
    current_connections_set = set()
    raw_connections = [] # Guardar conexiones completas por si necesitamos otros campos
    try:
        raw_connections = psutil.net_connections(kind='inet') # 'inet' incluye TCP y UDP (IPv4/IPv6)
        for conn in raw_connections:
            # Crear una tupla identificadora única para la conexión
            # Usamos None si la dirección remota no existe (sockets listening, etc.)
            conn_id = (
                conn.laddr.ip, conn.laddr.port,
                conn.raddr.ip if conn.raddr else None,
                conn.raddr.port if conn.raddr else None,
                conn.status, # Incluir estado porque una conexión cambia de estado (SYN_SENT -> ESTABLISHED)
                conn.pid # Incluir PID
            )
            current_connections_set.add(conn_id)

    except psutil.AccessDenied:
        log_event("Acceso denegado al listar conexiones de red. Ejecuta con permisos elevados.", "ERROR")
        # No podemos continuar sin la lista de conexiones
        return
    except Exception as e:
        log_event(f"Error al obtener lista de conexiones: {e}", "ERROR")
        return

    log_event(f"Conexiones actuales encontradas: {len(current_connections_set)}", "DEBUG")

    # 3. Comparar con el conjunto anterior para detectar eventos
    new_connections = current_connections_set - previous_connections_set
    closed_connections = previous_connections_set - current_connections_set

    log_event(f"Conexiones nuevas detectadas: {len(new_connections)}", "DEBUG")
    log_event(f"Conexiones cerradas detectadas: {len(closed_connections)}", "DEBUG")


    # 4. Registrar Eventos de Conexión Nuevas
    for conn_id in new_connections:
        l_ip, l_port, r_ip, r_port, status, pid = conn_id
        pid_str = str(pid) if pid else 'N/A'

        # Intentar obtener info del proceso usando el mapa del ciclo actual
        process_info = pid_info_map.get(pid)
        if process_info:
            p_name = process_info['name']
            p_path = process_info['path']
            p_cmdline = process_info['cmdline']
            p_user = process_info['username']
            details = f"User='{p_user}'"
        else:
            # Info del proceso no disponible (ej. terminó justo ahora o no tuvimos acceso)
            p_name = "Info no disponible"
            p_path = "Info no disponible"
            p_cmdline = "Info no disponible"
            details = "Proceso info no disponible"
            if pid is None: details = "PID no disponible"


        log_event(f"--> Conexión Abierta: PID={pid_str}, Nombre='{p_name}', {l_ip}:{l_port} -> {r_ip}:{r_port}, Estado='{status}'", "INFO")

        # Escribir en el CSV de eventos
        event_data = [
            timestamp, # Timestamp
            'ConnectionOpened', # EventType
            pid_str, # PID
            p_name, # ProcessName
            p_path, # ProcessPath
            p_cmdline, # ProcessCmdline
            f"{l_ip}:{l_port}", # LocalAddress
            f"{r_ip}:{r_port}" if r_ip is not None else 'N/A', # RemoteAddress
            status, # Status
            'TCP' if conn_id[5] == 1 else ('UDP' if conn_id[5] == 2 else 'Other'), # Protocol (esto requiere revisar conn.type en psutil.net_connections raw output, la tupla conn_id es simplificada) - CORRECCIÓN: type está en conn.type.name
            details # EventDetails (User, etc)
        ]
        # CORRECCIÓN: Obtener el tipo de protocolo correctamente
        original_conn = next((c for c in raw_connections if (c.laddr.ip, c.laddr.port, c.raddr.ip if c.raddr else None, c.raddr.port if c.raddr else None, c.status, c.pid) == conn_id), None)
        protocol = original_conn.type.name if original_conn else 'Unknown'
        event_data[9] = protocol # Actualizar el protocolo en la lista
        write_connection_event_csv(event_data)


    # 5. Registrar Eventos de Conexión Cerradas
    for conn_id in closed_connections:
        l_ip, l_port, r_ip, r_port, status, pid = conn_id # Estado aquí es el estado *final* conocido
        pid_str = str(pid) if pid else 'N/A'

        # Intentar obtener info del proceso. Es probable que el proceso ya no esté.
        # Aquí podríamos usar last_known_process_info si la hubiéramos persistido robustamente.
        # Por ahora, solo usamos el PID y marcamos como "Info no disponible" si no está en el mapa actual.
        process_info = pid_info_map.get(pid)
        if process_info:
             # Esto solo pasa si el proceso aún existe pero la conexión se cerró.
            p_name = process_info['name']
            p_path = process_info['path']
            p_cmdline = process_info['cmdline']
            p_user = process_info['username']
            details = f"User='{p_user}'"
        else:
            # Este es el caso común: el proceso terminó después de cerrar la conexión.
            p_name = f"PID {pid_str} (Terminado?)"
            p_path = "Info no disponible"
            p_cmdline = "Info no disponible"
            details = "Proceso info no disponible/terminado"
            if pid is None: details = "PID no disponible"


        log_event(f"--> Conexión Cerrada: PID={pid_str}, Nombre='{p_name}', {l_ip}:{l_port} -> {r_ip}:{r_port}, Estado='{status}' (Cierre)", "INFO")

        # Escribir en el CSV de eventos
        event_data = [
            timestamp, # Timestamp
            'ConnectionClosed', # EventType
            pid_str, # PID
            p_name, # ProcessName
            p_path, # ProcessPath
            p_cmdline, # ProcessCmdline
            f"{l_ip}:{l_port}", # LocalAddress
            f"{r_ip}:{r_port}" if r_ip is not None else 'N/A', # RemoteAddress
            status, # Status (Es el estado que tenía al ser detectada *antes* de cerrar)
            'Unknown', # Protocol (No tenemos el objeto 'conn' original aquí, puede ser Unknown o intentar inferir de puertos comunes)
            details # EventDetails
        ]
         # CORRECCIÓN: Intentar inferir protocolo básico o dejar como Unknown
         # Si el estado es LISTEN, suele ser TCP. Si no tiene raddr, puede ser TCP/UDP local.
         # Para ser precisos, necesitaríamos la info 'type' del objeto 'conn' original, que no está en conn_id.
         # Dejaremos Unknown o podemos añadir una columna para tipo en conn_id si es crucial.
         # Añadimos tipo a conn_id: (laddr_ip, laddr_port, raddr_ip, raddr_port, status, pid, type.name)
         # Para no cambiar la estructura de conn_id, simplemente lo marcamos como Unknown aquí.
         # OJO: La tupla conn_id DEBERÍA incluir el tipo para ser precisa en la comparación.
         # Vamos a rehacer conn_id para incluir el tipo.

        # --- REHACER conn_id para incluir el tipo ---
        # La estructura original de conn_id (laddr_ip, laddr_port, raddr_ip, raddr_port, status, pid)
        # no incluía el tipo (TCP/UDP), que es crucial para identificar la conexión.
        # La nueva estructura de conn_id será:
        # (laddr_ip, laddr_port, raddr_ip, raddr_port, status, pid, type_name)

        # Para los closed_connections, reconstruimos la tupla con el tipo (que sí estaba en el previous_connections_set)
        # Buscamos en previous_connections_set la tupla completa.
        original_conn_id_with_type = next((c for c in previous_connections_set if c[0:6] == conn_id), None)
        protocol = original_conn_id_with_type[6] if original_conn_id_with_type else 'Unknown'
        event_data[9] = protocol # Actualizar el protocolo

        write_connection_event_csv(event_data)


    # 6. Actualizar el estado de las conexiones para el próximo ciclo
    log_event(f"Actualizando estado de conexiones. Conexiones anteriores: {len(previous_connections_set)}, Conexiones actuales: {len(current_connections_set)}", "DEBUG")
    previous_connections_set = current_connections_set # El conjunto actual se convierte en el anterior

    log_event(f"--- Escaneo de conexiones finalizado [{timestamp}] ---")

# --- REHACER: Ajustar la tupla conn_id para incluir el tipo ---
def monitor_network_connections_corrected():
    """
    Monitorea conexiones de red, detecta eventos de apertura/cierre
    y los registra con info del proceso. Usa una tupla conn_id con protocolo.
    """
    global previous_connections_set
    log_event(f"\n--- Iniciando escaneo de conexiones [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ---")

    pid_info_map = get_process_info_map()
    log_event(f"Info de {len(pid_info_map)} procesos obtenida.", "DEBUG")

    current_connections_set = set()
    raw_connections = []
    try:
        raw_connections = psutil.net_connections(kind='inet')
        for conn in raw_connections:
            # Nueva estructura de tupla identificadora con tipo y familia
            conn_id = (
                conn.laddr.ip, conn.laddr.port,
                conn.raddr.ip if conn.raddr else None,
                conn.raddr.port if conn.raddr else None,
                conn.status,
                conn.pid,
                conn.type.name, # Añadir tipo (tcp/udp)
                conn.family.name # Añadir familia (ipv4/ipv6)
            )
            current_connections_set.add(conn_id)

    except psutil.AccessDenied:
        log_event("Acceso denegado al listar conexiones de red. Ejecuta con permisos elevados.", "ERROR")
        return
    except Exception as e:
        log_event(f"Error al obtener lista de conexiones: {e}", "ERROR")
        return

    log_event(f"Conexiones actuales encontradas: {len(current_connections_set)}", "DEBUG")

    new_connections = current_connections_set - previous_connections_set
    closed_connections = previous_connections_set - current_connections_set

    log_event(f"Conexiones nuevas detectadas: {len(new_connections)}", "DEBUG")
    log_event(f"Conexiones cerradas detectadas: {len(closed_connections)}", "DEBUG")

    # Registrar Eventos de Conexión Nuevas
    for conn_id in new_connections:
        l_ip, l_port, r_ip, r_port, status, pid, protocol, family = conn_id
        pid_str = str(pid) if pid else 'N/A'
        process_info = pid_info_map.get(pid)

        if process_info:
            p_name = process_info['name']
            p_path = process_info['path']
            p_cmdline = process_info['cmdline']
            p_user = process_info['username']
            details = f"User='{p_user}'"
        else:
            p_name = "Info no disponible"
            p_path = "Info no disponible"
            p_cmdline = "Info no disponible"
            details = "Proceso info no disponible/terminado"
            if pid is None: details = "PID no disponible"

        log_event(f"--> Conexión Abierta: PID={pid_str}, Nombre='{p_name}', {l_ip}:{l_port} -> {r_ip}:{r_port}, Proto={protocol}, Estado='{status}'", "INFO")

        event_data = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ConnectionOpened',
            pid_str,
            p_name,
            p_path,
            p_cmdline,
            f"{l_ip}:{l_port}",
            f"{r_ip}:{r_port}" if r_ip is not None else 'N/A',
            status,
            protocol,
            details
        ]
        write_connection_event_csv(event_data)


    # Registrar Eventos de Conexión Cerradas
    for conn_id in closed_connections:
        # conn_id aquí YA TIENE la información completa (incluido el estado final conocido y protocolo)
        l_ip, l_port, r_ip, r_port, status, pid, protocol, family = conn_id # Usar el estado de la tupla anterior
        pid_str = str(pid) if pid else 'N/A'
        process_info = pid_info_map.get(pid) # Intentar obtener info del proceso AHORA (puede haber terminado)

        if process_info:
             # Esto solo pasa si el proceso aún existe pero la conexión se cerró.
            p_name = process_info['name']
            p_path = process_info['path']
            p_cmdline = process_info['cmdline']
            p_user = process_info['username']
            details = f"User='{p_user}'"
        else:
            # Este es el caso común: el proceso terminó después de cerrar la conexión.
            p_name = f"PID {pid_str} (Terminado?)"
            p_path = "Info no disponible"
            p_cmdline = "Info no disponible"
            details = "Proceso info no disponible/terminado"
            if pid is None: details = "PID no disponible"


        log_event(f"--> Conexión Cerrada: PID={pid_str}, Nombre='{p_name}', {l_ip}:{l_port} -> {r_ip}:{r_port}, Proto={protocol}, Estado='{status}' (Al cerrar)", "INFO")

        event_data = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ConnectionClosed',
            pid_str,
            p_name,
            p_path,
            p_cmdline,
            f"{l_ip}:{l_port}",
            f"{r_ip}:{r_port}" if r_ip is not None else 'N/A',
            status, # Estado que tenía la conexión ANTES de cerrar (útil para saber si estaba ESTABLISHED, TIME_WAIT, etc.)
            protocol,
            details
        ]
        write_connection_event_csv(event_data)


    # 6. Actualizar el estado de las conexiones para el próximo ciclo
    log_event(f"Actualizando estado de conexiones. Conexiones anteriores: {len(previous_connections_set)}, Conexiones actuales: {len(current_connections_set)}", "DEBUG")
    previous_connections_set = current_connections_set


# --- Bucle Principal ---
log_event(f"Iniciando monitor de eventos de conexión por proceso.")
log_event(f"Host: {platform.node()} (Sistema: {platform.system()} {platform.release()})")
log_event(f"Usuario Ejecutando: {os.getenv('USERNAME') or os.getenv('USER')}", "INFO")
log_event(f"Intervalo de escaneo: {INTERVALO_SEGUNDOS} segundos")
log_event(f"Registrando en: {LOG_FILE_GENERAL} (general), {LOG_FILE_CONNECTIONS_CSV} (eventos CSV)")
log_event("Presiona Ctrl+C para detener.")
log_event("--- Inicio de Monitorización ---")

# Opcional: Realizar un escaneo inicial para poblar el estado
log_event("Realizando escaneo inicial para establecer la base de conexiones...")
try:
    # Llamamos a la función corregida para el primer escaneo
    monitor_network_connections_corrected()
    log_event("Escaneo inicial completado. El monitoreo de eventos comenzará en el próximo intervalo.")
except Exception as e:
    log_event(f"Error durante el escaneo inicial: {e}", "CRITICAL")
    # Decide si quieres salir o intentar continuar
    # exit(1) # Descomentar si quieres salir si falla el escaneo inicial


try:
    while True:
        # El bucle principal espera primero
        log_event(f"\nEsperando {INTERVALO_SEGUNDOS} segundos para el próximo ciclo...")
        time.sleep(INTERVALO_SEGUNDOS)

        # --- Inicio del Ciclo de Monitoreo ---
        # Llamamos a la función corregida en cada ciclo
        monitor_network_connections_corrected()


except KeyboardInterrupt:
    log_event("\nMonitorización detenida por el usuario.")
except Exception as e:
    log_event(f"\nSe produjo un error inesperado en el bucle principal: {e}", "CRITICAL")

log_event("--- Fin de Monitorización ---")