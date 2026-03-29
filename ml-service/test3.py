import requests
print(requests.post("http://localhost:8888/api/predict", json={"url": "http://localhost:8081/test-payloads/1_visual_spoof.html"}).json())
