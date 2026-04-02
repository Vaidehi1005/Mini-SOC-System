import requests

def scan_website(url):
    results = []

    payload = "' OR 1=1 --"
    response = requests.get(url + payload)

    if "error" in response.text.lower():
        results.append("Possible SQL Injection")

    return results