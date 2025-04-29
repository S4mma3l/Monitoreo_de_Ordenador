import os
import shutil
import hashlib
from datetime import datetime
import platform
import sys

# --- Configuración ---
# Carpeta donde se guardarán las copias de seguridad.
# !!! CAMBIA ESTO a una ubicación segura en un disco diferente si es posible,
#     idealmente un disco externo o una ubicación de red segura si aplica y es seguro.
#     Asegúrate de que la cuenta que ejecuta el script tenga permisos para escribir aquí.
DESTINO_BASE_BACKUP = "C:\\SecurityArtifactsCollection" # *** CAMBIA ESTO ***

# Lista de archivos y carpetas críticas de Windows a intentar copiar.
# Algunas pueden fallar debido a permisos o bloqueo de archivos (ej. hives de registro en uso).
# Usamos raw strings (r"...") para evitar problemas con backslashes en rutas de Windows.
# Agregamos Amcache.hve que estaba en la imagen.
ARCHIVOS_CRITICOS_WINDOWS = [
    # Credential & Security Stores (Live hives often locked)
    r"C:\Windows\System32\config\SAM",       # Likely locked (Live SAM hive)
    r"C:\Windows\repair\SAM",               # Usually copyable (Backup SAM hive)
    r"C:\Windows\System32\config\SECURITY",  # Likely locked (Live SECURITY hive)
    # System & Software Logs (Live hives often locked, Event Logs usually copyable)
    r"C:\Windows\System32\config\SOFTWARE",  # Likely locked (Live SOFTWARE hive)
    r"C:\Windows\System32\config\SYSTEM",    # Likely locked (Live SYSTEM hive)
    r"C:\Windows\System32\winevt\Logs",      # Directory containing .evtx files (usually copyable)
    # Recon & Persistence Analysis (Prefetch/Amcache usually copyable, NTUSER.DAT locked)
    r"C:\Windows\Prefetch",                  # Directory containing .pf files (usually copyable)
    r"C:\Windows\AppCompat\Programs\Amcache.hve", # Usually copyable (from image)
    # Nota: C:\Users\*\NTUSER.DAT es por usuario. El script intentará encontrar y copiar
    # NTUSER.DAT y las carpetas Startup de cada usuario válido encontrado en C:\Users.
    # La ruta base C:\Users está en la lista para activar el procesamiento de usuarios.
    r"C:\Users",
    # All Users Startup folder (User Startup está cubierto en el procesamiento de C:\Users)
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    # Otras rutas potencialmente interesantes, aunque no todas en la imagen, son comunes en análisis
    # r"C:\Windows\Tasks", # Scheduled Tasks (XML files)
    # r"C:\Windows\System32\Tasks", # System Scheduled Tasks
    # r"C:\Windows\System32\drivers\etc\hosts", # Hosts file
]

LOG_FILE = "security_artifact_collector.log"
# ---------------------

def log_message(message, level="INFO"):
    """Escribe un mensaje con timestamp y nivel al archivo de log y consola."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} [{level}] {message}"
    print(log_entry) # También imprimir en consola
    try:
        # Usar encoding='utf-8' para manejar nombres de archivo/ruta con caracteres especiales
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"ERROR: No se pudo escribir en el archivo de log {LOG_FILE}: {e}")

def get_file_hash(filepath, hash_algorithm='sha256'):
    """Calcula el hash de un archivo."""
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return f"N/A - Archivo no existe o no es archivo ({filepath})"

    try:
        hasher = hashlib.sha256() if hash_algorithm.lower() == 'sha256' else hashlib.md5()
        with open(filepath, 'rb') as f:
            # Leer en bloques grandes para archivos grandes
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError) as e:
        # Capturar errores comunes de acceso o sistema de archivos al intentar leer
        return f"N/A - Permiso denegado / Error SO: {e}"
    except Exception as e:
        return f"N/A - Error hash: {e}"

def secure_copy_item(source_path, destination_dir):
    """
    Intenta copiar un archivo o directorio a la carpeta de destino.
    Maneja errores comunes y registra el resultado.
    Devuelve True/False para éxito y un mensaje de resultado.
    Si es un archivo, devuelve la ruta de la copia exitosa y su hash si es posible.
    """
    item_name = os.path.basename(source_path)
    destination_path = os.path.join(destination_dir, item_name)
    copied_hash = "N/A" # Inicializar hash

    log_message(f"Intentando copiar: {source_path} a {destination_dir}")

    # 1. Verificar si el origen existe
    if not os.path.exists(source_path):
        log_message(f"  [ERROR] Origen no encontrado: {source_path}", "ERROR")
        return False, f"Origen no encontrado: {source_path}", copied_hash

    # 2. Asegurar que la carpeta de destino exista
    if not os.path.exists(destination_dir):
        try:
            os.makedirs(destination_dir, exist_ok=True) # exist_ok=True evita error si ya existe
            log_message(f"  Carpeta de destino creada: {destination_dir}", "DEBUG")
        except Exception as e:
            log_message(f"  [CRITICAL] No se pudo crear la carpeta de destino: {destination_dir} - {e}", "CRITICAL")
            return False, f"No se pudo crear destino: {e}", copied_hash

    # 3. Intentar la copia
    try:
        if os.path.isfile(source_path):
            # Copiar archivo, preservando metadatos tanto como sea posible
            shutil.copy2(source_path, destination_path)
            log_message(f"  [SUCCESS] Archivo copiado: {source_path}", "INFO")
            # Calcular hash del archivo copiado para verificar integridad
            copied_hash = get_file_hash(destination_path)
            log_message(f"    Hash SHA256 de la copia: {copied_hash}", "DEBUG")
            return True, destination_path, copied_hash # Devolver True, ruta de copia, hash

        elif os.path.isdir(source_path):
            # Copiar directorio. shutil.copytree requiere que el destino NO exista.
            # Vamos a copiar los contenidos uno por uno para un manejo más granular de errores por archivo.
            log_message(f"  Copiando contenido del directorio: {source_path}", "INFO")
            # Crear la carpeta de destino del directorio si no existe
            if not os.path.exists(destination_path):
                 os.makedirs(destination_path, exist_ok=True)

            success_count = 0
            fail_count = 0
            # No calculamos/retornamos todos los hashes de sub-archivos aquí, se logran en secure_copy_file recursivamente

            # Recorrer el directorio origen
            for root, dirs, files in os.walk(source_path):
                 # Determinar la subcarpeta relativa en el destino
                 relative_path = os.path.relpath(root, source_path)
                 current_dest_dir = os.path.join(destination_path, relative_path)

                 # Asegurar que la estructura de subdirectorios exista en el destino
                 if not os.path.exists(current_dest_dir):
                     try:
                         os.makedirs(current_dest_dir, exist_ok=True)
                     except Exception as e:
                         log_message(f"    [ERROR] No se pudo crear subcarpeta destino '{current_dest_dir}': {e}", "ERROR")
                         fail_count += len(files) # Considerar los archivos en esta carpeta como fallidos de copia indirectamente
                         continue # Pasar a la siguiente carpeta

                 for file_name in files:
                     source_file_path = os.path.join(root, file_name)
                     dest_file_path = os.path.join(current_dest_dir, file_name)
                     # Intentar copiar archivo individualmente usando la misma función
                     file_copied, file_result_msg, file_hash = secure_copy_item(source_file_path, current_dest_dir)
                     if file_copied:
                         success_count += 1
                         # El log y el hash ya se manejan dentro de la llamada recursiva
                     else:
                         fail_count += 1
                         log_message(f"    [ERROR] Falló copia de archivo '{file_name}' en '{source_path}': {file_result_msg}", "ERROR")


            log_message(f"  [SUCCESS] Directorio procesado: {source_path} (Archivos copiados: {success_count}, Fallidos: {fail_count})", "INFO")
            # Devolvemos True si se intentó copiar al menos un archivo o si el directorio estaba vacío
            return (success_count + fail_count) > 0, f"Directorio procesado. Archivos copiados: {success_count}, Fallidos: {fail_count}", copied_hash # Hash es N/A para directorios

        else:
            # No es ni archivo ni directorio (ej. un link simbólico, pipe con nombre, etc.)
            log_message(f"  [WARNING] Origen no es archivo ni directorio (saltando): {source_path}", "WARNING")
            return False, f"Origen no es archivo ni directorio: {source_path}", copied_hash

    except PermissionError:
        log_message(f"  [ERROR] Permiso denegado para copiar: {source_path}", "ERROR")
        return False, f"Permiso denegado para copiar: {source_path}", copied_hash
    except shutil.SameFileError:
        log_message(f"  [WARNING] Origen y destino son el mismo archivo (saltando): {source_path}", "WARNING")
        return False, f"Origen y destino son el mismo", copied_hash
    except IOError as e:
         # Este error a menudo indica que el archivo está en uso/bloqueado en Windows
         log_message(f"  [ERROR] Error de I/O (archivo en uso/bloqueado?): {source_path} - {e}", "ERROR")
         return False, f"Error de I/O (archivo en uso/bloqueado?): {e}", copied_hash
    except Exception as e:
        # Capturar cualquier otro error inesperado durante la copia
        log_message(f"  [ERROR] Error inesperado al copiar: {source_path} - {e}", "ERROR")
        return False, f"Error inesperado al copiar: {e}", copied_hash


def collect_critical_files():
    """Procede a recolectar los archivos y directorios críticos definidos."""
    log_message("--- Iniciando recolección de artefactos de seguridad críticos ---")
    log_message(f"Destino base de backup: {DESTINO_BASE_BACKUP}")

    if platform.system() != "Windows":
        log_message("  [WARNING] Este script está diseñado principalmente para Windows. Algunas rutas pueden no existir o comportarse diferente.", "WARNING")

    # Crear una carpeta de backup única con timestamp para esta ejecución
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    current_backup_dir = os.path.join(DESTINO_BASE_BACKUP, f"Collection_{timestamp_str}")

    log_message(f"Carpeta de colección para esta ejecución: {current_backup_dir}")
    try:
        os.makedirs(current_backup_dir, exist_ok=True)
        log_message("Carpeta de colección creada con éxito (o ya existía).", "INFO")
    except Exception as e:
        log_message(f"[CRITICAL] No se pudo crear la carpeta de colección principal: {current_backup_dir} - {e}", "CRITICAL")
        log_message("--- Recolección terminada con fallos (no se pudo crear el destino) ---", "ERROR")
        return # Salir si no podemos crear la carpeta de destino

    attempted_count = 0
    success_count = 0
    failed_items = [] # Lista para registrar los elementos que fallaron y la razón
    successful_hashes = {} # Diccionario para almacenar hashes de archivos copiados {ruta_en_backup: hash}


    # --- Procesar elementos de la lista principal ---
    # Iteramos sobre una copia de la lista si necesitamos modificarla durante la iteración,
    # pero aquí solo leemos, así que la lista original está bien.
    for source_item in ARCHIVOS_CRITICOS_WINDOWS:
        # Manejar caso especial de C:\Users para encontrar NTUSER.DAT y Startup folders por usuario
        if os.path.normpath(source_item.lower()) == os.path.normpath(r"C:\Users".lower()):
            log_message(f"Procesando perfiles de usuario encontrados en: {source_item}", "INFO")
            users_dir = source_item
            try:
                # Listar subdirectorios en C:\Users
                # Filtramos directorios comunes de sistema/públicos
                for entry_name in os.listdir(users_dir):
                    user_path = os.path.join(users_dir, entry_name)
                    # Comprobación básica para ver si parece un directorio de perfil de usuario válido
                    if os.path.isdir(user_path) and not entry_name.lower() in ['public', 'default', 'defaultuser', 'all users', 'desktop', 'public desktop'] and not entry_name.startswith('.'): # Añadir '.' para ocultos en Linux/macOS si se usa en otros OS
                         # Verificar si existe un NTUSER.DAT típico para considerar que es un perfil de usuario
                         if os.path.exists(os.path.join(user_path, "NTUSER.DAT")):
                            log_message(f"  Procesando perfil de usuario: {entry_name}", "INFO")
                            user_backup_dir = os.path.join(current_backup_dir, "Users", entry_name) # Carpeta de backup específica para este usuario

                            # --- Intentar copiar NTUSER.DAT del usuario ---
                            ntuser_dat_path = os.path.join(user_path, "NTUSER.DAT")
                            attempted_count += 1
                            copied, result_msg, file_hash = secure_copy_item(ntuser_dat_path, user_backup_dir)
                            if copied:
                                success_count += 1
                                successful_hashes[result_msg] = file_hash # result_msg es la ruta de la copia si es éxito archivo
                            else:
                                failed_items.append(f"{ntuser_dat_path} -> {result_msg}")
                                log_message(f"    [ERROR] Falló copia de NTUSER.DAT para '{entry_name}': {result_msg}", "ERROR")

                            # --- Intentar copiar la carpeta de Startup del usuario ---
                            user_startup_path = os.path.join(user_path, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
                            # Verificamos si la carpeta Startup existe antes de intentar copiar
                            if os.path.exists(user_startup_path):
                                 attempted_count += 1 # Contamos el intento de copiar la carpeta
                                 # secure_copy_item maneja el conteo interno de archivos copiados/fallidos dentro del directorio
                                 copied, result_msg, file_hash = secure_copy_item(user_startup_path, user_backup_dir) # file_hash será N/A para directorios
                                 if copied:
                                     success_count += 1 # Contamos 1 éxito si el directorio se procesó sin error crítico
                                     # Los hashes de los archivos dentro se logran en la función recursivamente
                                 else:
                                     failed_items.append(f"{user_startup_path} -> {result_msg}")
                                     log_message(f"    [ERROR] Falló copia de Startup para '{entry_name}': {result_msg}", "ERROR")
                            else:
                                log_message(f"    Carpeta Startup no encontrada para '{entry_name}'", "DEBUG")

                         # else: Es un directorio en C:\Users pero no parece un perfil de usuario (ej. AppData, etc.)
                         # log_message(f"  Saltando directorio en C:\Users que no parece perfil de usuario: {entry_name}", "DEBUG")


            except PermissionError:
                 log_message(f"  [ERROR] Permiso denegado al listar directorios en {users_dir}", "ERROR")
                 failed_items.append(f"{users_dir} -> Permiso denegado al listar perfiles")
            except Exception as e:
                 log_message(f"  [ERROR] Error al procesar perfiles de usuario en {users_dir}: {e}", "ERROR")
                 failed_items.append(f"{users_dir} -> Error al procesar perfiles: {e}")

        else:
            # --- Procesar otros archivos o directorios de la lista principal ---
            # Si el elemento no es la carpeta C:\Users, lo procesamos directamente
            attempted_count += 1
            copied, result_msg, file_hash = secure_copy_item(source_item, current_backup_dir)
            if copied:
                success_count += 1
                # Si es un archivo, almacenamos su hash. Si es un directorio, file_hash es N/A.
                if file_hash != "N/A":
                    successful_hashes[result_msg] = file_hash # result_msg es la ruta de la copia si es éxito archivo
            else:
                failed_items.append(f"{source_item} -> {result_msg}")
                log_message(f"  [ERROR] Falló la copia de '{source_item}': {result_msg}", "ERROR")


    # --- Resumen final ---
    log_message("\n" + "="*80)
    log_message(">>> RESUMEN DE RECOLECCIÓN DE ARTEFACTOS DE SEGURIDAD <<<", "INFO")
    log_message("="*80)
    log_message(f"Carpeta de colección: {current_backup_dir}", "INFO")
    log_message(f"Intentos de copia: {attempted_count}", "INFO")
    log_message(f"Elementos (archivos/directorios) procesados con éxito: {success_count}", "INFO")
    log_message(f"Elementos (archivos/directorios) que fallaron en la copia: {len(failed_items)}", "INFO")

    if failed_items:
        log_message("\n--- Elementos que fallaron en la copia ---", "WARNING")
        for item_fail in failed_items:
            log_message(f"  - {item_fail}", "WARNING")

    log_message("\n--- Hashes SHA256 de Archivos Copiados Exitosamente ---", "INFO")
    if successful_hashes:
        # Ordenar por ruta de archivo en el backup
        for copied_path, file_hash in sorted(successful_hashes.items()):
             # Mostramos la ruta relativa dentro del backup para mayor claridad
             relative_copied_path = os.path.relpath(copied_path, current_backup_dir)
             log_message(f"  {relative_copied_path}: {file_hash}", "INFO")
    else:
        log_message("  No se lograron copiar archivos individuales exitosamente para calcular hashes.", "WARNING")


    log_message("\n[NOTA IMPORTANTE]")
    log_message("La copia directa de archivos del sistema en uso (como hives de registro SAM, SYSTEM, SOFTWARE, SECURITY, y NTUSER.DAT del usuario actual) a menudo falla debido a bloqueos del sistema operativo.", "WARNING")
    log_message("Si estos fallaron, necesitarás técnicas más avanzadas para recolectarlos de forma forense, como:", "INFO")
    log_message("  - Usar Volume Shadow Copy Service (VSS) de Windows (requiere herramientas externas o scripting PowerShell/WMI).", "INFO")
    log_message("  - Utilizar herramientas forenses especializadas.", "INFO")
    log_message("  - Recolectar desde una copia de seguridad del sistema o imagen forense.", "INFO")
    log_message("\n[ACCIÓN REQUERIDA]")
    log_message("1. Revisa el log detallado arriba para ver qué falló y por qué.", "INFO")
    log_message("2. Asegúrate de ejecutar el script con permisos de Administrador.", "INFO")
    log_message(f"3. **Asegura la carpeta de colección '{current_backup_dir}'**. Contiene datos sensibles.", "CRITICAL")


    log_message("\n--- Recolección de artefactos terminada ---", "INFO")


# --- Ejecución principal ---
if __name__ == "__main__":
    # Verificar que se está ejecutando en Windows
    if platform.system() != "Windows":
        log_message("[CRITICAL] Este script está diseñado solo para sistemas Windows. Las rutas definidas son específicas de Windows.", "CRITICAL")
        sys.exit(1) # Salir si no es Windows

    # Verificar que se está ejecutando con permisos elevados (heurística básica en Windows)
    # Intenta crear una carpeta temporal en System32 - esto fallará sin admin
    # Usamos un nombre con PID y timestamp para ser lo más únicos posible
    test_path = os.path.join(r"C:\Windows\System32", f"TestPerms_{os.getpid()}_{datetime.now().strftime('%f')}")
    is_admin = False
    try:
        os.makedirs(test_path)
        os.rmdir(test_path) # Limpiar inmediatamente
        is_admin = True
        log_message("Detectado que se está ejecutando con permisos elevados (Administrador).", "INFO")
    except PermissionError:
        is_admin = False
        log_message("[CRITICAL] Este script requiere permisos de Administrador para acceder a archivos críticos. Por favor, haz clic derecho sobre el archivo Python o la terminal y selecciona 'Ejecutar como administrador'.", "CRITICAL")
    except Exception as e:
        # Otros errores inesperados al verificar permisos
        log_message(f"No se pudo verificar permisos elevados ({e}). Intentando continuar, pero es probable que falle si no es Administrador.", "WARNING")
        # Aquí no salimos, porque puede que el error no signifique que no sea admin,
        # o que algunas copias sí funcionen incluso sin admin completo para todas las rutas.

    # Proceder con la recolección solo si es admin O si la verificación falló de otra manera (para dar la oportunidad)
    # Si la verificación de Permiso Denegado ocurrió, no procedemos.
    if is_admin or (not is_admin and "No se pudo verificar permisos elevados" in open(LOG_FILE, 'r', encoding='utf-8').read()): # Heurística: verificar si el log tiene el mensaje de verificación fallida no-Permiso Denegado
        collect_critical_files()
    else:
         log_message("Script no ejecutado porque no se detectaron permisos de Administrador.", "INFO")