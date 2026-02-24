import shodan


class ShodanSearch:
    """
    Client wrapper for Shodan searches.

    Parameters:
        api_key (str): Shodan API key.
    """

    def __init__(self, api_key: str):
        if not api_key or not api_key.strip():
            raise ValueError("Shodan API key is missing or empty.")
        self.client = shodan.Shodan(api_key.strip())

    def search(self, query: str, page: int = 1) -> dict:
        """
        Execute a Shodan search query.

        Args:
            query (str): Shodan query (e.g., 'http.title:dvwa').
            page (int): Result page number (>= 1).

        Returns:
            dict: Shodan API response.

        Raises:
            ValueError: If query is empty or page is invalid.
            shodan.APIError: If Shodan API returns an error.
        """
        if not query or not query.strip():
            raise ValueError("Query must not be empty.")
        if page < 1:
            raise ValueError("Page must be >= 1.")

        # Let shodan.APIError bubble up to the caller for clean handling
        return self.client.search(query.strip(), page=page)
