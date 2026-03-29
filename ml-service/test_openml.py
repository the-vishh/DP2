import sklearn.datasets
print("Fetching from OpenML...")
try:
    data = sklearn.datasets.fetch_openml(name='PhishingWebsites', version=1, parser='auto')
    print("Downloaded!", data.data.shape)
except Exception as e:
    print("Error:", e)
