import urllib.request
import os

print("Downloading real phishing and benign URL datasets...")

# Legit domains (Tranco top 10k list)
print("Downloading top benign domains...")
urllib.request.urlretrieve("https://tranco-list.eu/download/K2VGQ/10000", "benign_urls.csv")

# Phishing domains (OpenPhish feed or similar)
print("Downloading recent phishing domains...")
req = urllib.request.Request('https://openphish.com/feed.txt', headers={'User-Agent': 'Mozilla/5.0'})
try:
    with urllib.request.urlopen(req) as response:
        with open("phishing_urls.txt", "wb") as out_file:
            out_file.write(response.read())
    print("Download complete.")
except Exception as e:
    print(f"OpenPhish download failed: {e}")

