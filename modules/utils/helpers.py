# helpers.py
def filter_query_urls(urls, domain):
    """
    Visszaadja azokat az URL-eket, amik a domain-t tartalmazzák,
    '=' karaktert és http[s] prefixet.
    """
    return [u for u in set(urls) if domain in u and "=" in u and u.startswith("http")]
