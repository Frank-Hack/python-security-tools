from waybackpy import WaybackMachineCDXServerAPI
from datetime import datetime, timedelta
import requests

class HistoricalSearch:
    """Clase para buscar y recuperar capturas históricas de páginas web mediante la API de Wayback Machine.

    Attributes:
        url (str): URL del sitio web para buscar sus versiones anteriores.
        user_agent (str): Cadena de agente de usuario utilizada para las peticiones HTTP.
    """
    
    def __init__(self, url, user_agent):
        """Inicializa la clase con la URL y el agente de usuario.

        Args:
            url (str): URL del sitio web a investigar.
            user_agent (str): Agente de usuario para realizar las solicitudes.
        """
        self.url = url
        self.user_agent = user_agent

    def search_snapshot(self, years_ago=10, filename="snapshot.html"):
        """Busca una captura cerca de una fecha específica y la guarda en un archivo.

        Args:
            years_ago (int, optional): Número de años atrás desde el día actual para buscar la captura. Por defecto es 10.
            filename (str, optional): Nombre del archivo donde se guardará la captura. Por defecto es 'snapshot.html'.

        Returns:
            None: Resultados impresos en la consola.
        """
        target_date = datetime.now() - timedelta(days=365 * years_ago)
        year, month, day = target_date.year, target_date.month, target_date.day

        cdx_api = WaybackMachineCDXServerAPI(self.url, self.user_agent)
        snapshot = cdx_api.near(year=year, month=month, day=day)

        if snapshot:
            print(f"Fecha: {snapshot.timestamp}, URL: {snapshot.archive_url}")
            self.download_snapshot(snapshot.archive_url, filename)
        else:
            print("No se encontró ninguna captura para la fecha especificada.")

    def download_snapshot(self, archive_url, filename):
        """Descarga el contenido de una captura de Wayback Machine y lo guarda en un archivo.

        Args:
            archive_url (str): URL de la captura en Wayback Machine.
            filename (str): Nombre del archivo donde se guardará la captura.

        Returns:
            None: Resultados impresos en la consola.
        """
        response = requests.get(archive_url)
        if response.status_code == 200:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(response.text)
            print(f"Documento guardado exitosamente en {filename}")
        else:
            print(f"Error al descargar la página. Código de estado: {response.status_code}")

    def search_snapshots_by_extensions(self, years_ago=4, days_interval=30, extensions=None, match_type="domain"):
        """Busca capturas por tipo de archivo en un intervalo de tiempo específico.

        Args:
            years_ago (int): Años atrás para comenzar la búsqueda.
            days_interval (int): Duración del intervalo en días desde el comienzo de la búsqueda.
            extensions (list, optional): Lista de extensiones de archivo para filtrar las capturas.
            match_type (str, optional): Tipo de coincidencia para la búsqueda en Wayback Machine.

        Returns:
            None: Resultados impresos en la consola.
        """
        if extensions is None:
            extensions = ["pdf", "doc", "docx", "ppt", "xls", "xlsx", "txt"]

        today = datetime.now()
        start_period = (today - timedelta(days=365 * years_ago)).strftime('%Y%m%d')
        end_period = (today - timedelta(days=(365 * years_ago) - days_interval)).strftime('%Y%m%d')

        cdx_api = WaybackMachineCDXServerAPI(url=self.url, user_agent=self.user_agent,
                                             start_timestamp=start_period, end_timestamp=end_period,
                                             match_type=match_type)
        regex_filter = "(" + "|".join([f".*\\.{ext}$" for ext in extensions]) + ")"
        cdx_api.filters = [f"urlkey:{regex_filter}"]

        snapshots = cdx_api.snapshots()
        for snapshot in snapshots:
            print(f"Fecha: {snapshot.timestamp}, URL: {snapshot.archive_url}")


if __name__ == "__main__":
    user_agent = "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0"
    url = "github.com"

    hsearch = HistoricalSearch(url, user_agent)

    # hsearch.search_snapshot()
    hsearch.search_snapshots_by_extensions(years_ago=1, days_interval=100)
