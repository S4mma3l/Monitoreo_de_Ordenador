# Suite de Monitoreo y Análisis de Seguridad Local con Python

## Descripción del Proyecto

Esta suite de scripts Python está diseñada para ayudar a un analista de seguridad a obtener visibilidad y analizar la actividad de procesos y red en una máquina local (endpoint). Los scripts se dividen en monitores (que recopilan datos continuamente) y analizadores (que examinan los datos recopilados).

## Propósito

El objetivo principal es detectar posibles Indicadores de Compromiso (IoCs) o actividades anómalas en un endpoint, tales como:

* Ejecutables con hashes inesperados o modificados.
* Procesos ejecutándose desde rutas inusuales.
* Actividad de red (conexiones abiertas/cerradas) asociada a procesos específicos.
* Destinos de red (IPs/puertos) poco comunes o sospechosos contactados por procesos locales.
* Puertos locales inesperados en estado de escucha (LISTEN).
* Patrones en la línea de comandos asociados a actividad de red o procesos inusuales.

## Prerrequisitos

* Python 3.6 o superior instalado.
* La biblioteca `psutil` instalada. Puedes instalarla usando pip:
    ```bash
    pip install psutil
    ```
* Permisos de administrador/root para ejecutar los scripts de monitorización. Esto es necesario para acceder a la información completa de todos los procesos y conexiones del sistema.

## Instalación

1.  Descarga los cuatro archivos `.py` (`System_Monitor.py`, `System_Verify.py`, `Network_Monitor.py`, `Network_Verify.py`).
2.  Colócalos todos en la misma carpeta.
3.  Asegúrate de tener Python y `psutil` instalados (ver Prerrequisitos).

## Configuración

**ES CRUCIAL configurar los scripts editando las constantes al principio de cada archivo (`.py`) antes de ejecutarlos.**

* **`System_Monitor.py`**:
    * `INTERVALO_SEGUNDOS`: Frecuencia del escaneo de procesos y trazado de red (ej. 120 para 2 minutos).
    * `DESTINO_TRAZADO`: **Cambia esto** a una IP o nombre de host relevante en tu red interna (ej. la IP de un servidor de dominio, un router, etc.).
    * `LOG_FILE_GENERAL`, `LOG_FILE_PROCESS`: Nombres de los archivos de log/CSV de salida.
    * `RUTAS_SOSPECHOSAS_BASICAS`: Lista de fragmentos de ruta a considerar sospechosos.
* **`System_Verify.py`**:
    * `LOG_FILE_PROCESS_CSV`: Asegúrate de que coincida con el archivo CSV generado por `System_Monitor.py`.
    * `LOW_OCCURRENCE_THRESHOLD`: Umbral para considerar hashes/rutas/cmdlines como "poco comunes" (ej. vistos N veces o menos).
    * `SUSPICIOUS_PATHS_FRAGMENT`: Lista de fragmentos de ruta a considerar sospechosos (debe coincidir con `System_Monitor.py` para análisis cruzado).
* **`Network_Monitor.py`**:
    * `INTERVALO_SEGUNDOS`: Frecuencia del escaneo de conexiones (intervalo corto recomendado, ej. 10 segundos).
    * `LOG_FILE_GENERAL`, `LOG_FILE_CONNECTIONS_CSV`: Nombres de los archivos de log/CSV de salida.
* **`Network_Verify.py`**:
    * `LOG_FILE_CONNECTIONS_CSV`: Asegúrate de que coincida con el archivo CSV generado por `Network_Monitor.py`.
    * `INTERNAL_IP_RANGES_CIDR`: **Configura tus rangos de IP internos** en formato CIDR (ej. `["192.168.1.0/24", "10.0.0.0/8"]`). Esto es vital para clasificar conexiones internas vs. externas.
    * `LOW_OCCURRENCE_THRESHOLD`: Umbral para considerar IPs/puertos/procesos remotos como "poco comunes" en los eventos de conexión.
    * `SUSPICIOUS_PATHS_FRAGMENT`: Lista de fragmentos de ruta sospechosa (debe coincidir con los monitores para análisis cruzado).

## Descripción de los Archivos

* ### `System_Monitor.py`
    * **Función:** Monitorea continuamente los procesos del sistema y realiza un trazado de red periódico. Captura detalles como PID, nombre, usuario, ruta del ejecutable, línea de comandos, hash SHA256 del ejecutable y conexiones activas en el momento del escaneo. Detecta y alerta sobre procesos nuevos que aparecen durante la monitorización.
    * **Ejecución Recomendada:** Ejecutar con permisos elevados en segundo plano (`python System_Monitor.py`). Detener con `Ctrl+C`. Dejarlo correr por un período para recopilar datos.
    * **Archivos de Salida:**
        * `monitor_seguridad_local_general.log`: Log general con timestamps, alertas (ej. proceso nuevo), y resultados del trazado de red.
        * `monitor_seguridad_local_procesos.csv`: CSV estructurado con los detalles completos de cada proceso escaneado en cada intervalo.

* ### `System_Verify.py`
    * **Función:** Analiza el archivo `monitor_seguridad_local_procesos.csv`. Busca casos donde el mismo nombre de proceso (`ProcessName`) aparece con **diferentes** `Hash SHA256`, `Ruta Ejecutable` o `Línea de Comandos`. Reporta estas variaciones y proporciona contexto (PID/Usuario/Conexiones de ejemplo).
    * **Ejecución Recomendada:** Ejecutar manualmente (`python System_Verify.py`) después de que `System_Monitor.py` haya recopilado datos significativos y haya sido detenido.
    * **Salida:** Reporte detallado en la consola, destacando los nombres de proceso con variaciones detectadas y las combinaciones únicas encontradas para cada uno.

* ### `Network_Monitor.py`
    * **Función:** Monitorea continuamente los eventos de conexión de red (apertura y cierre) por proceso. Registra qué proceso (PID, nombre, ruta, cmdline) inició o cerró una conexión, y los detalles de la conexión (direcciones local/remota, puerto, estado, protocolo).
    * **Ejecución Recomendada:** Ejecutar con permisos elevados en segundo plano (`python Network_Monitor.py`). Detener con `Ctrl+C`. Dejarlo correr en paralelo con `System_Monitor.py` para correlacionar eventos. Utiliza un intervalo de escaneo más corto que `System_Monitor.py`.
    * **Archivos de Salida:**
        * `network_monitor_general.log`: Log general con timestamps y mensajes de estado.
        * `network_connection_events.csv`: CSV estructurado con una fila por cada **evento** (apertura o cierre) de conexión detectado.

* ### `Network_Verify.py`
    * **Función:** Analiza el archivo `network_connection_events.csv`. Proporciona un panorama agregado de la actividad de red registrada, incluyendo resumen general, top talkers (procesos, IPs/Puertos remotos), elementos poco comunes (bajo conteo), puertos locales en escucha, y conexiones provenientes de procesos con rutas potencialmente sospechosas.
    * **Ejecución Recomendada:** Ejecutar manualmente (`python Network_Verify.py`) después de que `Network_Monitor.py` haya recopilado datos significativos y haya sido detenido.
    * **Salida:** Reporte resumido en la consola, destacando estadísticas clave y posibles áreas de interés para la seguridad.

## Flujo de Trabajo / Uso

1.  **Preparación:** Asegúrate de que Python y `psutil` estén instalados y que los 4 archivos `.py` estén en la misma carpeta.
2.  **Configuración:** Edita las constantes en los 4 archivos `.py` para adaptarlos a tu entorno (IPs, rangos de red, nombres de archivo si es necesario, etc.).
3.  **Monitorización:** Abre **dos terminales/símbolos del sistema diferentes con permisos de administrador/root** en la carpeta de los scripts.
    * En la primera terminal, ejecuta `python System_Monitor.py`.
    * En la segunda terminal, ejecuta `python Network_Monitor.py`.
    * Deja que ambos monitores se ejecuten en paralelo durante un período que consideres adecuado para capturar actividad (varias horas, un día, etc.).
4.  **Detención:** Cuando hayas terminado de recopilar datos, ve a cada terminal y presiona `Ctrl+C` para detener los scripts de monitorización de forma segura.
5.  **Análisis:** Abre una nueva terminal en la misma carpeta (no necesita permisos elevados a menos que los archivos de log estén protegidos).
    * Ejecuta `python System_Verify.py` para analizar los datos de procesos/hashes/rutas.
    * Ejecuta `python Network_Verify.py` para analizar los datos de eventos de conexión de red.
6.  **Revisión:** Analiza cuidadosamente la salida impresa en la consola por los scripts `_Verify.py`. Revisa también los archivos `.log` y `.csv` generados directamente para un análisis más detallado (puedes abrir los CSV en Excel o usar herramientas como `pandas` en Python).

## Limitaciones Importantes

* **Monitoreo Local:** Esta suite solo monitoriza la **máquina específica** donde se ejecuta. No proporciona una vista de toda la red empresarial.
* **Análisis Post-Mortem (Principalmente):** Los scripts `_Verify.py` analizan datos *después* de ser recopilados. No hay alerta en tiempo real integrada en la consola cuando algo sospechoso ocurre.
* **No es un SIEM/EDR:** Esto no reemplaza las soluciones de seguridad de nivel empresarial (SIEM, EDR, NDR). Es una herramienta básica para ganar visibilidad local.
* **No Mide Volumen de Datos:** Los monitores de red registran eventos de conexión, pero no la cantidad de bytes transferidos por cada conexión.
* **Inteligencia de Amenazas Limitada:** La comparación con amenazas conocidas requiere pasos manuales (copiar hash/IP y buscar en VirusTotal, etc.) o la integración con fuentes de TI (fuera del alcance de estos scripts).
* **Heurísticas Básicas:** Las detecciones (rutas sospechosas, bajo conteo) se basan en heurísticas simples y pueden generar falsos positivos o no detectar amenazas sofisticadas.
* **Requiere Permisos Elevados:** Los monitores necesitan altos permisos para funcionar correctamente.

## Descargo de Responsabilidad

Estos scripts son herramientas básicas con fines educativos y de análisis de seguridad local. Úsalos de forma responsable y **asegúrate de cumplir con las políticas de seguridad de tu organización** antes de implementarlos en un entorno empresarial. El autor no se hace responsable del uso indebido de estos scripts.

---