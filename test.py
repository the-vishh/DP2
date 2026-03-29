import requests

try:
    resp = requests.post("http://localhost:8000/predict/url", json={"url": "http://localhost:8081/test-payloads/1_visual_spoof.html"})
    print(resp.json())
except Exception as e:
    print("Error:", e)
