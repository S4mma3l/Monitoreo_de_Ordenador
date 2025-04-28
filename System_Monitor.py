import time
import subprocess
import platform
import psutil
import os
from datetime import datetime
import csv
import hashlib # Para calcular hashes
# import json # Opcional: si decides guardar estado o config en JSON

# --- Configuración ---
INTERVALO_SEGUNDOS = 120  # 2 minutos
DESTINO_TRAZADO = "8.8.8.8" # <-- *** CAMBIA ESTO *** a una IP o nombre de host en tu red
LOG_FILE_GENERAL = "monitor_seguridad_local_general.log"
LOG_FILE_PROCESS = "monitor_seguridad_local_procesos.csv" # Usaremos CSV para procesos
# ---------------------

# Rutas de ejemplo consideradas potencialmente sospechosas (puedes expandir esta lista)
# Asegúrate de usar os.path.join y convertir a minúsculas para comparación consistente
RUTAS_SOSPECHOSAS_BASICAS = [
    os.path.join(os.getenv("TEMP", ""), "").lower(), # Carpeta temporal de usuario
    os.path.join(os.getenv("APPDATA", ""), "Local", "Temp", "").lower(), # Otra temp de usuario
    os.path.join(os.getenv("USERPROFILE", ""), "Downloads", "").lower(), # Carpeta de Descargas
    "c:\\windows\\temp\\", # Carpeta temporal de Windows
    "/tmp/", "/var/tmp/", # Carpetas temporales en Linux/macOS
]

# Mantenemos un estado global (simple en memoria) de los PIDs vistos en el ciclo anterior
# Para una solución más robusta, esto se guardaría en un archivo al finalizar y se cargaría al inicio.
previous_pids = set()
# previous_process_details = {} # Opcional: guardar detalles si necesitas comparar más que solo existencia de PID

def log_general(message, level="INFO"):
    """Escribe un mensaje con timestamp y nivel al archivo de log general."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} [{level}] {message}"
    print(log_entry) # También imprimir en consola
    try:
        with open(LOG_FILE_GENERAL, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"ERROR: No se pudo escribir en el archivo de log general {LOG_FILE_GENERAL}: {e}")

def get_file_hash(filepath, hash_algorithm='sha256'):
    """Calcula el hash de un archivo."""
    if not filepath or not os.path.exists(filepath):
        return "N/A - Archivo no encontrado"
    if not os.path.isfile(filepath):
         return "N/A - No es un archivo"

    try:
        hasher = hashlib.sha256() if hash_algorithm.lower() == 'sha256' else hashlib.md5()
        # Usar 'with open' para asegurar que el archivo se cierre correctamente
        with open(filepath, 'rb') as f:
            # Leer en bloques grandes para archivos grandes
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        # Capturar errores comunes de acceso o sistema de archivos
        return "N/A - Permiso denegado / Error SO"
    except Exception as e:
        return f"N/A - Error hash: {e}"

def realizar_trazado(destino):
    """Realiza un trazado de red al destino especificado y lo registra."""
    log_general(f"Iniciando trazado a {destino}...")
    sistema_operativo = platform.system()

    # Comandos y opciones específicos para cada OS
    if sistema_operativo == "Windows":
        comando = ["tracert", "-d", "-w", "1000", "-h", "30", destino] # -d: no resolver nombres, -w 1000ms timeout, -h 30 hops max
    else: # Linux, macOS, etc.
        comando = ["traceroute", "-n", "-w", "1", "-m", "30", destino] # -n: no resolver nombres, -w 1s timeout, -m 30 hops max

    try:
        # Ejecutar el comando, capturando salida y errores
        # timeout es importante para que el script no se cuelgue si el trazado falla
        proceso = subprocess.run(comando, capture_output=True, text=True, timeout=40)
        log_general("--- Resultado del Trazado ---", "DEBUG") # Marca el inicio del resultado en el log general
        log_general(proceso.stdout, "DEBUG") # Registrar la salida estándar (el trazado)
        if proceso.stderr:
            log_general("Error en el trazado:", "WARNING")
            log_general(proceso.stderr, "WARNING") # Registrar la salida de error si la hay
    except FileNotFoundError:
        log_general(f"Error: Comando '{comando[0]}' no encontrado. ¿Está instalado el traceroute/tracert?", "ERROR")
    except subprocess.TimeoutExpired:
        log_general("Error: El comando de trazado excedió el tiempo límite.", "WARNING")
    except Exception as e:
        log_general(f"Error general al ejecutar el trazado: {e}", "ERROR")

def es_ruta_sospechosa(ruta_ejecutable):
    """Verifica si la ruta del ejecutable está en una ubicación sospechosa básica."""
    if not ruta_ejecutable:
        return False
    ruta_lower = ruta_ejecutable.lower()
    for ruta_sospechosa_base in RUTAS_SOSPECHOSAS_BASICAS:
        # Usar startswith para chequear si la ruta empieza con alguna de las bases sospechosas
        if ruta_lower.startswith(ruta_sospechosa_base):
            return True
    return False

def analizar_proceso(proc_info):
    """Analiza la información de un proceso individual desde una perspectiva de seguridad."""
    # --- FIX: Declarar 'previous_pids' como global ---
    global previous_pids
    # --- Fin FIX ---

    pid = proc_info['pid']
    name = proc_info.get('name', 'N/A')
    username = proc_info.get('username', 'N/A') or 'N/A' # psutil.username puede retornar None
    cmdline_list = proc_info.get('cmdline')
    cmdline = " ".join(cmdline_list) if cmdline_list else ""
    exe_path = proc_info.get('exe', 'N/A')
    ppid = proc_info.get('ppid', 'N/A')
    status = proc_info.get('status', 'N/A')
    cpu_percent = proc_info.get('cpu_percent', 0.0)
    memory_percent = proc_info.get('memory_percent', 0.0)

    log_entry_general = f"Proceso: PID={pid}, Nombre='{name}', Usuario='{username}'"
    log_general(log_entry_general)
    log_general(f"  Ruta: '{exe_path}'", "DEBUG")
    log_general(f"  Cmd: '{cmdline}'", "DEBUG")
    log_general(f"  Recursos: CPU={cpu_percent:.1f}%, Mem={memory_percent:.1f}%, Estado={status}", "DEBUG")

    # --- Análisis de Seguridad ---

    # 1. Hash del Ejecutable
    file_hash = get_file_hash(exe_path)
    log_general(f"  Hash (SHA256): {file_hash}")

    # 2. Detección de Proceso Nuevo
    if pid not in previous_pids: # <--- Aquí se usa previous_pids
        log_general(f"  !!! ALERTA: Nuevo proceso detectado: {name} (PID: {pid})", "WARNING")
    # Nota: La detección de cambios en ruta/cmdline para PIDs persistentes es más compleja
    # y requeriría guardar los detalles del proceso anterior en 'previous_process_details'.


    # 3. Análisis de Rutas Sospechosas
    if es_ruta_sospechosa(exe_path):
        log_general(f"  !!! ALERTA: Ruta de ejecutable potencialmente sospechosa: '{exe_path}'", "WARNING")

    # 4. Detección de Masquerading Básico (Ejemplo: svchost.exe fuera de System32 en Windows)
    sistema_operativo = platform.system()
    if sistema_operativo == "Windows":
        if name.lower() == 'svchost.exe' and 'system32' not in str(exe_path).lower(): # Asegurar que exe_path es string
            log_general(f"  !!! ALERTA: Posible Masquerading - svchost.exe fuera de System32: '{exe_path}'", "WARNING")
    # Puedes añadir más reglas aquí para otros nombres comunes si lo necesitas


    # 5. Conexiones de Red del Proceso
    connections_list = [] # Para guardar las conexiones de este proceso para el CSV
    try:
        # Usar psutil.Process(pid).connections() es a veces más robusto que proc.connections()
        process_connections = psutil.Process(pid).connections(kind='inet')
        if process_connections:
            log_general("  Conexiones de red:")
            for conn in process_connections:
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A'
                conn_info = f"{conn.type.name} {conn.status}: {local_addr} -> {remote_addr}"
                log_general(f"    - {conn_info}")
                connections_list.append(conn_info) # Añadir al listado para el CSV
        else:
            log_general("  Sin conexiones de red activas para este proceso.", "DEBUG")

    except psutil.AccessDenied:
        log_general("  Acceso denegado para listar conexiones de este proceso.", "WARNING")
        connections_list.append("Acceso Denegado")
    except psutil.NoSuchProcess:
         # El proceso terminó justo mientras intentábamos obtener conexiones
         log_general("  Proceso terminado al intentar obtener conexiones.", "DEBUG")
         connections_list.append("Proceso Terminado")
    except Exception as e:
         log_general(f"  Error al obtener conexiones del proceso: {e}", "ERROR")
         connections_list.append(f"Error: {e}")
    # -------------------------------------

    log_general("-" * 20, "DEBUG") # Separador en el log general

    # Retornar los datos para el CSV
    return [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        pid,
        name,
        username,
        exe_path,
        cmdline,
        ppid,
        f"{cpu_percent:.1f}",
        f"{memory_percent:.1f}",
        status,
        file_hash,
        "; ".join(connections_list) # Unir las conexiones en una sola cadena para el CSV
    ]


def listar_procesos_y_conexiones():
    """Lista procesos con detalles de seguridad, sus conexiones, y detecta nuevos/sospechosos. Registra en CSV."""
    global previous_pids # Declaramos que vamos a modificar la variable global
    log_general("Iniciando listado y análisis de procesos...")

    current_pids_set = set() # Conjunto para los PIDs vistos en este ciclo
    process_data_for_csv = [] # Lista para almacenar los datos a escribir en el CSV

    # Encabezados para el archivo CSV de procesos
    csv_headers = [
        'Timestamp', 'PID', 'Nombre', 'Usuario', 'Ruta Ejecutable',
        'Línea de Comandos', 'PPID', 'CPU%', 'Mem%', 'Estado', 'Hash SHA256',
        'Conexiones' # Esta columna contendrá las conexiones separadas por '; '
    ]

    # Determinar si necesitamos escribir los encabezados en el CSV (si el archivo es nuevo)
    csv_mode = 'a' # Modo append por defecto
    if not os.path.exists(LOG_FILE_PROCESS):
         csv_mode = 'w' # Modo write si es la primera vez
         # Abrir y escribir encabezados INMEDIATAMENTE si es modo 'w'
         with open(LOG_FILE_PROCESS, mode='w', newline='', encoding='utf-8') as csvfile:
              csv_writer = csv.writer(csvfile)
              csv_writer.writerow(csv_headers)


    try:
        # Iterar sobre todos los procesos con atributos relevantes
        # psutil.process_iter es un generador, procesa de a uno a la vez
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent',
                                        'cmdline', 'exe', 'ppid', 'status']):
            # --- FIX: Capturar PID temprano para usarlo en errores ---
            current_pid = None # Inicializar la variable del PID actual
            try:
                current_pid = proc.pid # <-- Obtener el PID AQUI. Esto rara vez falla si el proceso existe.
                current_pids_set.add(current_pid) # Añadir al conjunto de PIDs actuales

                # Intentar obtener el resto de la información del proceso.
                # Acceder a proc.info AQUI es el punto más común donde AccessDenied puede ocurrir.
                pinfo = proc.info

                # Analizar y obtener datos para CSV usando pinfo.
                # La función analizar_proceso ahora accede a previous_pids directamente como global.
                row_data = analizar_proceso(pinfo)
                process_data_for_csv.append(row_data)


            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                # Captura si el proceso desapareció mientras lo iterábamos O si es un zombie
                pass # Ignorar procesos que ya no existen o son zombies

            except psutil.AccessDenied:
                 # Captura errores de permiso al intentar obtener info (pinfo) del proceso
                 # Usamos el PID capturado al inicio del try
                 log_general(f"Acceso denegado al procesar PID {current_pid}.", "DEBUG")
                 # No podemos obtener info detallada ni hash ni conexiones, simplemente lo saltamos para este ciclo.
                 # No lo añadimos a process_data_for_csv.
                 pass
            except Exception as e:
                 # Otros errores inesperados al procesar un proceso particular
                 # Usamos el PID capturado al inicio del try
                 log_general(f"Error inesperado al procesar el proceso con posible PID {current_pid}: {e}", "ERROR")


    except Exception as e:
        # Captura errores generales al iniciar la iteración de procesos
        log_general(f"Error general al listar procesos: {e}", "CRITICAL")

    # --- Escribir los datos de los procesos al archivo CSV ---
    # Esto se hace UNA VEZ al final de listar todos los procesos en el ciclo actual
    try:
        # Abrimos el archivo CSV en modo 'a' (append)
        # Si csv_mode era 'w', ya escribimos los encabezados arriba.
        with open(LOG_FILE_PROCESS, mode='a', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Escribimos las filas de datos recopilados
            csv_writer.writerows(process_data_for_csv)
        log_general(f"Datos de {len(process_data_for_csv)} procesos registrados en {LOG_FILE_PROCESS}")

    except Exception as e:
        log_general(f"ERROR: No se pudo escribir datos de procesos en {LOG_FILE_PROCESS}: {e}")

    # --- Actualizar el estado de PIDs para el próximo ciclo ---
    # Esto debe hacerse después de que todo el procesamiento del ciclo actual termine exitosamente (o con errores manejados)
    global previous_pids # Asegurarnos de modificar la variable global
    log_general(f"Actualizando estado de PIDs. PIDs anteriores: {len(previous_pids)}, PIDs actuales: {len(current_pids_set)}", "DEBUG")
    previous_pids = current_pids_set # El conjunto actual se convierte en el conjunto anterior para el próximo ciclo


def listar_conexiones_generales():
    """Lista todas las conexiones de red activas en el sistema, registrando la info."""
    log_general("Iniciando listado de conexiones de red generales (netstat-like)...")
    try:
        # psutil.net_connections() lista todas las conexiones del sistema
        conexiones = psutil.net_connections(kind='inet') # Filtrar por conexiones de internet (TCP/UDP)

        if conexiones:
            log_general("--- Listado General de Conexiones (netstat-like) ---", "DEBUG")
            # Columnas: Tipo, Estado, Dir Local, Dir Remota, PID (si disponible), Nombre Proceso (si disponible)
            log_general(f"{'Tipo':<5} {'Estado':<15} {'Dir Local':<25} {'Dir Remota':<25} {'PID':<8} {'Nombre Proceso'}", "DEBUG")
            log_general("-" * 100, "DEBUG") # Ajustar ancho de línea

            for conn in conexiones:
                 local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                 # conn.raddr es un namedtuple (ip, port) o None
                 remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A'
                 pid = conn.pid if conn.pid else 'N/A' # PID puede ser None para algunas conexiones del sistema (ej. kernel)
                 process_name = "N/A"
                 if conn.pid: # Si hay PID, intenta obtener el nombre del proceso
                     try:
                         process_name = psutil.Process(conn.pid).name()
                     except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                         process_name = "Desconocido/Restringido" # Proceso ya no existe o no tenemos acceso

                 log_general(f"{conn.type.name:<5} {conn.status:<15} {local_addr:<25} {remote_addr:<25} {str(pid):<8} {process_name}", "DEBUG")

            log_general("-" * 100, "DEBUG") # Ajustar ancho de línea
        else:
            log_general("No se encontraron conexiones de red activas generales.", "DEBUG")

    except psutil.AccessDenied:
        log_general("Acceso denegado para listar conexiones generales (netstat-like).", "WARNING")
    except Exception as e:
        log_general(f"Error al listar conexiones generales: {e}", "ERROR")


# --- Bucle Principal ---
log_general(f"Iniciando monitorización de seguridad local.")
log_general(f"Host: {platform.node()} (Sistema: {platform.system()} {platform.release()})")
log_general(f"Usuario Ejecutando: {os.getenv('USERNAME') or os.getenv('USER')}", "INFO") # USERNAME en Windows, USER en Linux/macOS
log_general(f"Trazado a: {DESTINO_TRAZADO}")
log_general(f"Intervalo: {INTERVALO_SEGUNDOS} segundos")
log_general(f"Registrando en: {LOG_FILE_GENERAL} (general), {LOG_FILE_PROCESS} (procesos CSV)")
log_general("Presiona Ctrl+C para detener.")
log_general("--- Inicio de Monitorización ---")

# Primer ciclo para inicializar el estado de PIDs antes del bucle principal
# Esto asegura que el primer ciclo no reporte TODOS los procesos como "nuevos"
log_general("Realizando primer escaneo para inicializar estado de PIDs...")
# Temporalmente silenciamos la salida de procesos detallada para esta inicialización
# Esto es una simple forma de evitar log detallado en el primer ciclo solo para estado
_original_log_process_csv = LOG_FILE_PROCESS # Guardamos el nombre original
LOG_FILE_PROCESS = "/dev/null" if platform.system() != "Windows" else "NUL" # Redirigir a null/NUL para silenciar CSV
_original_log_general = log_general # Guardamos la función original de log
def log_general(message, level="INFO"):
    if level != "DEBUG": # Solo mostramos INFO, WARNING, ERROR durante la inicialización 'silenciosa'
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{level}] {message}")
    # No escribimos a archivo durante esta inicialización

try:
    # Ejecutamos listar_procesos_y_conexiones una vez para poblar previous_pids
    # Esto generará logs (posiblemente silenciados) pero el objetivo es solo actualizar el estado global
    listar_procesos_y_conexiones()
except Exception as e:
    print(f"Error durante el escaneo inicial de estado: {e}")
finally:
    # Restaurar la configuración de log
    LOG_FILE_PROCESS = _original_log_process_csv
    log_general = _original_log_general
    log_general("Estado inicial de PIDs capturado. La monitorización normal comenzará pronto.")


try:
    while True:
        # El bucle principal espera primero, excepto la primera vez (que ya pasó)
        log_general(f"\nEsperando {INTERVALO_SEGUNDOS} segundos para el próximo ciclo...")
        time.sleep(INTERVALO_SEGUNDOS)

        # --- Inicio del Ciclo ---
        log_general(f"\n{'='*70}")
        log_general(f"Ciclo de Monitorización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        log_general(f"{'='*70}")

        realizar_trazado(DESTINO_TRAZADO)
        listar_procesos_y_conexiones() # Esta función actualiza el estado de PIDs para el próximo ciclo
        listar_conexiones_generales()

except KeyboardInterrupt:
    log_general("\nMonitorización detenida por el usuario.")
except Exception as e:
    log_general(f"\nSe produjo un error inesperado en el bucle principal: {e}", "CRITICAL")

log_general("--- Fin de Monitorización ---")