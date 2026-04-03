import requests

def scan_url(url):
    results = []

    # SQL Injection test
    try:
        r = requests.get(url + "' OR 1=1 --")
        if "error" in r.text.lower():
            results.append("⚠ SQL Injection possible")
    except:
        results.append("Error in SQL scan")

    # XSS test
    try:
        payload = "<script>alert(1)</script>"
        r = requests.get(url + payload)
        if payload in r.text:
            results.append("⚠ XSS vulnerability")
    except:
        results.append("Error in XSS scan")

    return results