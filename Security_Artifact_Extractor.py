import os
import shutil
import hashlib
from datetime import datetime
import platform
import sys
import csv # Para quizás exportar hallazgos estructurados si es necesario
# Importar librerías para parsear EVTX
try:
    from Evtx.Evtx import FileEvtx
    from Evtx.Views import EvtxXmlV # Importamos EvtxXmlV aunque no la usemos directamente en este ejemplo
    import xml.etree.ElementTree as ET # Para parsear el XML de los eventos
except ImportError:
    print("[-] Error: La biblioteca 'python-evtx' no está instalada.")
    print("    Por favor, instálala con: pip install python-evtx")
    sys.exit(1)


# --- Configuración ---
# Archivos de log para el propio script de extracción
LOG_FILE_EXTRACTION = "security_data_extraction.log"
# Directorios y archivos a analizar
# Nota: Nos enfocamos en rutas de donde podemos EXTRAER DATOS fácilmente con Python + python-evtx
# Las hives de registro y Amcache/Prefetch binarios requieren herramientas más avanzadas.
TARGET_ANALYSIS_PATHS = {
    "Startup Folders": [
        # C:\Users\* se procesará para encontrar AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", # All Users Startup
    ],
    "Event Logs (EVTX)": [
        # Rutas comunes de logs de eventos. Añade más si es necesario.
        r"C:\Windows\System32\winevt\Logs\Security.evtx",
        r"C:\Windows\System32\winevt\Logs\System.evtx",
        r"C:\Windows\System32\winevt\Logs\Application.evtx",
        # r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx", # Si Sysmon está instalado
        # r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx", # Logs de PowerShell
    ]
    # Prefetch (.pf), Amcache (.hve), Registry Hives (.hiv, .dat) se mencionan en las limitaciones.
}

# Event IDs de Windows a buscar en los logs de seguridad (ejemplos comunes)
# Puedes añadir o modificar esta lista según tu interés.
# 4624: Successful logon
# 4625: Failed logon
# 4688: Process Creation (requiere política de auditoría o Sysmon)
# 4672: Assign Special Privileges (ej. admin logon)
# 4720: A user account was created
# 4726: A user account was deleted
# ... y otros según el log (System, Application)
SECURITY_EVENT_IDS_OF_INTEREST = [4624, 4625, 4688, 4672, 4720, 4726]

# Event IDs de Windows a buscar en los logs del sistema (ejemplos)
SYSTEM_EVENT_IDS_OF_INTEREST = [
    7045, # Service Installed
    7036, # Service Entered Running State
    7034, # Service Crashed
    # 1000, # Application Error (Application log, not System)
    # ... etc.
]

# --- Procesamiento de Usuarios (Necesario para encontrar Startup y NTUSER.DAT - aunque no parsearemos NTUSER.DAT aquí) ---
# Esta parte es similar al script collector para encontrar rutas de usuario.
def get_user_profile_paths():
    # --- FIX: Usar raw string en el docstring para evitar error ---
    r"""Intenta encontrar las rutas a los perfiles de usuario en r'C:\Users'."""
    # --- Fin FIX ---
    users_dir = r"C:\Users"
    user_paths = []
    if platform.system() != "Windows" or not os.path.exists(users_dir):
        log_analysis_finding(f"[-] Directorio de usuarios '{users_dir}' no encontrado o no es Windows.", level="WARNING")
        return []

    try:
        for entry_name in os.listdir(users_dir):
            user_path = os.path.join(users_dir, entry_name)
            # Comprobación básica para ver si parece un directorio de perfil de usuario válido
            if os.path.isdir(user_path) and not entry_name.lower() in ['public', 'default', 'defaultuser', 'all users'] and not entry_name.startswith('.'): # Añadir '.' para ocultos en Linux/macOS si se usa en otros OS
                 # Verificar si existe un NTUSER.DAT típico para confirmar que es un perfil
                 if os.path.exists(os.path.join(user_path, "NTUSER.DAT")):
                     user_paths.append(user_path)
                     log_analysis_finding(f"[+] Perfil de usuario encontrado: {entry_name}", level="DEBUG")
                 # else: log_analysis_finding(f"[-] Directorio '{entry_name}' en C:\Users no parece perfil válido.", level="DEBUG")


    except PermissionError:
        log_analysis_finding(f"[CRITICAL] Permiso denegado al listar directorios en {users_dir}. No se pueden analizar perfiles de usuario.", level="CRITICAL")
        return []
    except Exception as e:
        log_analysis_finding(f"[ERROR] Error al listar directorios en {users_dir}: {e}", level="ERROR")
        return []
    return user_paths


def log_analysis_finding(message, level="INFO"):
    """Escribe un mensaje con timestamp y nivel al archivo de log de extracción y consola."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} [{level}] {message}"
    print(log_entry) # También imprimir en consola
    try:
        with open(LOG_FILE_EXTRACTION, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"ERROR: No se pudo escribir en el archivo de log de extracción {LOG_FILE_EXTRACTION}: {e}")

def get_file_hash(filepath, hash_algorithm='sha256'):
    """Calcula el hash de un archivo."""
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return f"N/A - Archivo no existe o no es archivo ({filepath})"

    try:
        hasher = hashlib.sha256() if hash_algorithm.lower() == 'sha256' else hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError) as e:
        return f"N/A - Permiso denegado / Error SO: {e}"
    except Exception as e:
        return f"N/A - Error hash: {e}"


# --- Funciones de Análisis Específicas ---

def analyze_startup_folders():
    """Analiza archivos en las carpetas de inicio de usuario y todos los usuarios."""
    log_analysis_finding("\n--- Analizando Carpetas de Inicio (Startup) ---")

    startup_paths = []
    # Añadir la carpeta All Users Startup
    startup_paths.append(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    # Añadir las carpetas Startup de cada usuario
    user_profiles = get_user_profile_paths()
    for user_path in user_profiles:
        user_startup = os.path.join(user_path, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        startup_paths.append(user_startup)

    found_items = 0
    for folder_path in startup_paths:
        # Asegurarse de que la ruta existe antes de intentar listar
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            log_analysis_finding(f"[*] Escaneando carpeta: {folder_path}")
            try:
                # Listar elementos en la carpeta
                for item_name in os.listdir(folder_path):
                    item_path = os.path.join(folder_path, item_name)
                    # Evitar directorios recursivos si los hay (normalmente no hay en Startup)
                    if os.path.isfile(item_path):
                        found_items += 1
                        # Obtener metadatos y hash del archivo
                        try:
                            file_size = os.path.getsize(item_path)
                            # Nota: getctime/getmtime/getatime pueden variar su significado entre OS/File Systems
                            # mtime: last modification time (más útil para ver cuándo se puso el archivo)
                            mtime_ts = os.path.getmtime(item_path)
                            mtime_dt = datetime.fromtimestamp(mtime_ts).strftime('%Y-%m-%d %H:%M:%S')
                            file_hash = get_file_hash(item_path)

                            log_analysis_finding(f"  [+] Item encontrado: {item_name}")
                            log_analysis_finding(f"      Ruta: '{item_path}'")
                            log_analysis_finding(f"      Tamaño: {file_size} bytes, Modificado: {mtime_dt}")
                            log_analysis_finding(f"      Hash SHA256: {file_hash}")
                            # --- Interpretación para el analista ---
                            log_analysis_finding("      [INTERPRETACIÓN] Cualquier archivo .exe, .vbs, .ps1, .bat, .lnk, etc. en esta carpeta se ejecuta automáticamente.", level="INFO")
                            if file_hash.startswith("N/A"):
                                log_analysis_finding("      [ALERTA] No se pudo obtener el hash. Puede ser un problema de permisos o archivo inaccesible. Investigar.", level="WARNING")
                            # Puedes añadir más heurísticas aquí (ej. nombres raros, extensiones inusuales)
                            # ---------------------------------------

                        except PermissionError:
                            log_analysis_finding(f"  [ERROR] Permiso denegado para acceder a '{item_path}'", level="ERROR")
                        except Exception as e:
                            log_analysis_finding(f"  [ERROR] Error al procesar item '{item_name}': {e}", level="ERROR")

            except PermissionError:
                log_analysis_finding(f"[ERROR] Permiso denegado para listar contenido de '{folder_path}'", level="ERROR")
            except Exception as e:
                log_analysis_finding(f"[ERROR] Error al escanear carpeta '{folder_path}': {e}", level="ERROR")
        # else: # Si la carpeta no existe, simplemente la saltamos y lo indicamos en el log general si es necesario
        #     log_analysis_finding(f"[-] Carpeta no encontrada (saltando): {folder_path}", level="DEBUG")


    if found_items == 0:
        log_analysis_finding("[*] No se encontraron archivos directamente ejecutables en las carpetas de inicio escaneadas.", level="INFO")
        log_analysis_finding("    [NOTA] Esto no excluye la persistencia por Registro (Run keys), Servicios, Tareas Programadas, etc.", level="INFO")

    log_analysis_finding("--- Fin Análisis Carpetas de Inicio ---")


def analyze_event_logs():
    """Analiza archivos de Event Logs (.evtx) buscando Event IDs de interés."""
    log_analysis_finding("\n--- Analizando Archivos de Event Logs (EVTX) ---")

    for log_filepath in TARGET_ANALYSIS_PATHS["Event Logs (EVTX)"]:
        if not os.path.exists(log_filepath) or not os.path.isfile(log_filepath):
            log_analysis_finding(f"[-] Archivo de Event Log no encontrado: {log_filepath}", level="WARNING")
            continue

        log_analysis_finding(f"[*] Procesando archivo EVTX: {log_filepath}")
        events_processed = 0
        events_of_interest_count = 0

        # Determinar qué Event IDs buscar en este archivo específico
        ids_to_look_for = []
        log_name = os.path.basename(log_filepath)
        if "Security.evtx" in log_name:
            ids_to_look_for = SECURITY_EVENT_IDS_OF_INTEREST
            log_type = "Security"
        elif "System.evtx" in log_name:
             ids_to_look_for = SYSTEM_EVENT_IDS_OF_INTEREST
             log_type = "System"
        # Puedes añadir más logs y sus IDs de interés aquí si es necesario
        # elif "Application.evtx" in log_name: ids_to_look_for = APPLICATION_EVENT_IDS_OF_INTEREST

        if not ids_to_look_for:
             log_analysis_finding(f"[-] No hay Event IDs de interés configurados para '{log_name}'. Saltando análisis detallado.", level="INFO")
             continue


        try:
            # Usar FileEvtx para abrir el archivo .evtx
            with FileEvtx(log_filepath) as evtx_file:
                log_analysis_finding(f"    Total de eventos en el archivo: {evtx_file.length()}", level="DEBUG")
                # Iterar sobre cada registro (evento) en el archivo
                # Nota: Para archivos EVTX muy grandes, esto puede consumir mucha memoria o tiempo.
                # python-evtx tiene opciones para procesar en chunks si es necesario.
                for record in evtx_file.records():
                    events_processed += 1
                    # Obtener la representación XML del evento
                    xml_content = record.xml()

                    try:
                        # Parsear el XML para extraer campos clave
                        root = ET.fromstring(xml_content)
                        # Buscar EventID en cualquier namespace
                        event_id_element = root.find('.//{*}EventID')
                        if event_id_element is not None:
                            try:
                                event_id = int(event_id_element.text)

                                # Verificar si el Event ID es de interés para este tipo de log
                                if event_id in ids_to_look_for:
                                    events_of_interest_count += 1
                                    # Extraer otros campos relevantes
                                    time_created_element = root.find('.//{*}TimeCreated')
                                    timestamp = time_created_element.get('SystemTime') if time_created_element is not None else 'N/A'

                                    computer_element = root.find('.//{*}Computer')
                                    computer = computer_element.text if computer_element is not None else 'N/A'

                                    # Extraer EventData - esto varía mucho según el Event ID
                                    # Intentamos extraer todos los elementos <Data> con atributo Name
                                    event_data_fields = {}
                                    event_data_element = root.find('.//{*}EventData')
                                    if event_data_element is not None:
                                        for data_element in event_data_element.findall('.//{*}Data'):
                                             name = data_element.get('Name')
                                             value = data_element.text
                                             if name:
                                                 event_data_fields[name] = value

                                    # --- Registrar y Interpretar el Evento de Interés ---
                                    log_analysis_finding(f"  [!] Evento de Interés Encontrado (ID: {event_id})", level="INFO")
                                    log_analysis_finding(f"      Log: {os.path.basename(log_filepath)}, Timestamp: {timestamp}")
                                    log_analysis_finding(f"      Computadora: {computer}") # Usuario/SID a menudo está en EventData (ej. Security ID)

                                    # Interpretación básica según Event ID (Ejemplos)
                                    if event_id in [4624, 4625]: # Successful/Failed Logon (Security Log)
                                        logon_status = "EXITOSO" if event_id == 4624 else "FALLIDO"
                                        target_user = event_data_fields.get('TargetUserName', 'N/A')
                                        source_ip = event_data_fields.get('IpAddress', 'N/A')
                                        logon_type = event_data_fields.get('LogonType', 'N/A')
                                        log_analysis_finding(f"      Tipo: Logon {logon_status}")
                                        log_analysis_finding(f"      Usuario Objetivo: {target_user}, IP Origen: {source_ip}, Tipo Logon: {logon_type}")
                                        if event_id == 4625 and source_ip not in ['-', '::1', '127.0.0.1']:
                                            log_analysis_finding("      [ALERTA] ¡Logon fallido desde IP remota/inusual! Investigar origen de IP y usuario.", level="WARNING")
                                        elif event_id == 4624 and logon_type in ['2', '10']: # 2: Interactive, 10: RemoteInteractive (RDP)
                                            log_analysis_finding(f"      [NOTA] Logon interactivo ({logon_type}). Verificar si es esperado.", level="DEBUG")

                                    elif event_id == 4688: # Process Creation (Security Log - si está habilitado)
                                         new_process_name = event_data_fields.get('NewProcessName', 'N/A')
                                         command_line = event_data_fields.get('CommandLine', 'N/A')
                                         creator_process_id = event_data_fields.get('CreatorProcessId', 'N/A')
                                         creator_process_name = event_data_fields.get('CreatorProcessName', 'N/A') # A menudo añadido por Sysmon
                                         log_analysis_finding(f"      Tipo: Creación de Proceso")
                                         log_analysis_finding(f"      Proceso Creado: '{new_process_name}'")
                                         log_analysis_finding(f"      Línea de Comandos: '{command_line}'")
                                         log_analysis_finding(f"      Padre PID: {creator_process_id}, Padre Nombre: '{creator_process_name}'")
                                         # [INTERPRETACIÓN] Analizar si el proceso/cmdline es inusual. Buscar LOLBins, nombres sospechosos, cmdlines codificados.
                                         log_analysis_finding("      [INTERPRETACIÓN] Analizar nombre del proceso, línea de comandos y proceso padre.", level="INFO")


                                    elif event_id in [4720, 4726]: # Account Created/Deleted (Security Log)
                                         target_user = event_data_fields.get('TargetUserName', 'N/A')
                                         log_analysis_finding(f"      Tipo: Cuenta de usuario {'creada' if event_id == 4720 else 'eliminada'}: {target_user}", level="WARNING")
                                         log_analysis_finding("      [ALERTA] Investigar si esta gestión de cuenta fue autorizada.", level="WARNING")

                                    elif event_id in [7045]: # Service Installed (System Log)
                                         service_name = event_data_fields.get('ServiceName', 'N/A')
                                         image_path = event_data_fields.get('ImagePath', 'N/A')
                                         service_type = event_data_fields.get('ServiceType', 'N/A')
                                         start_type = event_data_fields.get('StartType', 'N/A')
                                         log_analysis_finding(f"      Tipo: Servicio Instalado: '{service_name}'", level="WARNING")
                                         log_analysis_finding(f"      Ruta Ejecutable: '{image_path}', Tipo Servicio: {service_type}, Tipo Inicio: {start_type}", level="WARNING")
                                         log_analysis_finding("      [ALERTA] Investigar este servicio. Malware a menudo se instala como servicio.", level="WARNING")


                                    else: # Para otros Event IDs de interés, mostrar campos clave genéricos si existen
                                        log_analysis_finding(f"      Datos del Evento: {event_data_fields}", level="DEBUG") # Mostrar todos los campos para debug


                                    log_analysis_finding("-" * 20, level="DEBUG") # Separador en el log


                            except ValueError:
                                # Error al convertir EventID a int, o al obtener algún campo
                                log_analysis_finding(f"    [ERROR] Error al obtener Event ID o campos clave del Evento {record.record_id} en '{os.path.basename(log_filepath)}': Error de valor o formato.", level="ERROR")
                            except Exception as e:
                                log_analysis_finding(f"    [ERROR] Error inesperado al procesar Evento {record.record_id} en '{os.path.basename(log_filepath)}': {e}", level="ERROR")

                        else:
                            # Evento sin EventID (raro pero posible en logs corruptos)
                             log_analysis_finding(f"    [WARNING] Evento {record.record_id} en '{os.path.basename(log_filepath)}' sin EventID.", level="WARNING")


                    except ET.ParseError:
                        log_analysis_finding(f"    [ERROR] Error al parsear XML del Evento {record.record_id} en '{os.path.basename(log_filepath)}'. Evento posiblemente corrupto.", level="ERROR")
                    except Exception as e:
                         log_analysis_finding(f"    [ERROR] Error inesperado al intentar parsear Evento {record.record_id} XML en '{os.path.basename(log_filepath)}': {e}", level="ERROR")


        except PermissionError:
            log_analysis_finding(f"[ERROR] Permiso denegado para leer el archivo EVTX: {log_filepath}. Ejecuta con permisos elevados.", level="CRITICAL")
        except FileNotFoundError:
             log_analysis_finding(f"[ERROR] Archivo EVTX no encontrado durante el procesamiento: {log_filepath}", level="ERROR")
        except Exception as e:
            log_analysis_finding(f"[ERROR] Error general al procesar archivo EVTX '{log_filepath}': {e}", level="CRITICAL")

        log_analysis_finding(f"[*] Procesamiento de '{os.path.basename(log_filepath)}' completado. Eventos procesados: {events_processed}, Eventos de interés encontrados: {events_of_interest_count}", level="INFO")


    log_analysis_finding("--- Fin Análisis Archivos EVTX ---")


# --- Nota sobre otros artefactos (Prefetch, Amcache, Hives de Registro) ---
# El parsing robusto de estos archivos binarios es complejo en Python sin bibliotecas especializadas adicionales
# o herramientas externas. Mencionamos cómo se analizan típicamente:
def mention_other_artifacts_analysis():
    log_analysis_finding("\n--- Análisis de Otros Artefactos (Prefetch, Amcache, Hives de Registro) ---")
    log_analysis_finding("La extracción y análisis detallado del contenido de Prefetch (.pf), Amcache (.hve), y Hives de Registro (.hiv, .dat) requiere herramientas y bibliotecas especializadas.", level="INFO")
    log_analysis_finding("Estos archivos contienen información valiosa:", level="INFO")
    log_analysis_finding("  - Prefetch (" + r"C:\Windows\Prefetch" + "): Evidencia de ejecución de programas, tiempos, archivos/directorios accedidos.", level="INFO")
    log_analysis_finding("  - Amcache.hve (" + r"C:\Windows\AppCompat\Programs\Amcache.hve" + "): Más detalles sobre ejecutables que se han corrido, hashes, tiempos.", level="INFO")
    log_analysis_finding("  - Hives de Registro (SAM, SECURITY, SYSTEM, SOFTWARE, NTUSER.DAT): Cuentas de usuario, políticas, software instalado, configuraciones, puntos de persistencia (Run keys, etc.).", level="INFO")
    log_analysis_finding("\n[RECOMENDACIONES DE HERRAMIENTAS EXTERNAS]", level="INFO")
    log_analysis_finding("Para analizar estos artefactos (idealmente recolectados con el script de recolección anterior):", level="INFO")
    log_analysis_finding("  - Hives de Registro: Registry Explorer (Eric Zimmerman), RegRipper, regipy (biblioteca Python para análisis programático).", level="INFO")
    log_analysis_finding("  - Prefetch: Prefetch Parser (Eric Zimmerman), PECmd (Eric Zimmerman).", level="INFO")
    log_analysis_finding("  - Amcache.hve: Amcache Parser (Eric Zimmerman), AppCompatCacheParser.", level="INFO")
    log_analysis_finding("  - Event Logs (.evtx): Visor de Eventos de Windows, Evtx Explorer, PowerShell (Get-WinEvent).", level="INFO")
    log_analysis_finding("\nEste script no realiza este análisis binario profundo ni parseo exhaustivo de todos los logs directamente.", level="INFO")
    log_analysis_finding("--- Fin Nota Otros Artefactos ---")


# --- Ejecución principal ---
if __name__ == "__main__":
    log_analysis_finding("--- Iniciando Extracción y Análisis de Datos de Seguridad ---")
    log_analysis_finding(f"Host: {platform.node()} (Sistema: {platform.system()} {platform.release()})")
    log_analysis_finding(f"Usuario Ejecutando: {os.getenv('USERNAME') or os.getenv('USER')}", "INFO")
    log_analysis_finding(f"Log de extracción: {LOG_FILE_EXTRACTION}", "INFO")
    log_analysis_finding("-" * 40)

    if platform.system() != "Windows":
        log_analysis_finding("[CRITICAL] Este script está diseñado solo para sistemas Windows.", "CRITICAL")
        # No salimos directamente, solo alertamos, para permitir ver las secciones de nota sobre otros artefactos.

    # --- Realizar Análisis ---
    analyze_startup_folders()
    analyze_event_logs()
    mention_other_artifacts_analysis() # Incluir la nota sobre otros artefactos


    log_analysis_finding("\n--- Extracción y Análisis de Datos de Seguridad Finalizado ---")
    log_analysis_finding(f"Resultados detallados registrados en: {LOG_FILE_EXTRACTION}", "INFO")

    # NOTA: La ejecución de este script para ciertos logs o carpetas puede requerir permisos de Administrador.
    # Si experimentas errores de "Permiso denegado", ejecuta el script con permisos elevados.