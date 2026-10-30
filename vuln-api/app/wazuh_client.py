import os
import requests
import base64
from urllib.parse import urlparse, quote

VULN_INDEX = "wazuh-states-vulnerabilities-*"
VERIFY_SSL = os.getenv("VERIFY_SSL", "True").lower() == "true"
DOMAINS_ALLOWLIST = os.getenv("DOMAINS_ALLOWLIST", "localhost").split(",")

def is_safe_url(url: str) -> bool:
    hostname = urlparse(url).hostname
    return hostname in DOMAINS_ALLOWLIST

def get_auth_header(user, password):
    """Genera el header de autenticación en Base64."""
    auth_str = f"{user}:{password}"
    encoded_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {encoded_auth}", "Content-Type": "application/json"}

def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str):
    if not is_safe_url(indexer_url):
        raise ValueError(f"URL no permitida: {indexer_url}")
        
    parsed = urlparse(indexer_url)
    safe_base_url = f"{parsed.scheme}://{parsed.netloc}{quote(parsed.path)}"
    
    # 1. Iniciamos el contexto de scroll
    url = f"{safe_base_url}/{VULN_INDEX}/_search?scroll=2m"
    headers = get_auth_header(wazuh_user, wazuh_password)
    body = {
        "size": 5000, # Tamaño por lote
        "_source": True,
        "query": {"match_all": {}}
    }

    all_hits = []
    scroll_id = None
    try:
        resp = requests.post(url, json=body, headers=headers, verify=VERIFY_SSL, timeout=300)
        resp.raise_for_status()
        
        data = resp.json()
        scroll_id = data.get("_scroll_id")
        hits = data.get("hits", {}).get("hits", [])

        while hits:
            all_hits.extend([h["_source"] for h in hits])
            print(f"Fetched {len(all_hits)} vulns...")

            # 2. Pedimos el siguiente lote
            scroll_resp = requests.post(
                f"{safe_base_url}/_search/scroll",
                json={
                    "scroll": "2m",
                    "scroll_id": scroll_id
                },
                headers=headers,
                verify=VERIFY_SSL,
                timeout=60
            )
            scroll_resp.raise_for_status()
            
            scroll_data = scroll_resp.json()
            # Actualizamos el scroll_id y los hits para la siguiente iteración
            scroll_id = scroll_data.get("_scroll_id")
            hits = scroll_data.get("hits", {}).get("hits", [])

    finally:
        # 3. Limpieza: Liberar el scroll en el servidor
        if scroll_id:
            try:
                requests.delete(
                    f"{safe_base_url}/_search/scroll",
                    json={"scroll_id": [scroll_id]},
                    headers=headers,
                    verify=VERIFY_SSL,
                    timeout=10
                )
            except Exception as e:
                print(f"Error limpiando scroll: {e}")

    return all_hits


def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    if not is_safe_url(indexer_url):
        print(f"Connection test failed: URL not in allowlist ({indexer_url})")
        return False
    try:
        parsed = urlparse(indexer_url)
        # Construir la URL garantizando que el path está debidamente sanitizado con quote()
        safe_url = f"{parsed.scheme}://{parsed.netloc}{quote(parsed.path)}"
        
        headers = get_auth_header(wazuh_user, wazuh_password)
        resp = requests.get(
            safe_url,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=10
        )
        print(f"Connection test response: {resp.status_code} - {resp.text}")
        return resp.status_code == 200
    except Exception as e:
        print(f"Error testing connection: {e}")
        return False