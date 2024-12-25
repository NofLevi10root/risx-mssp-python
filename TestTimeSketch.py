from timesketch_api_client import client
import urllib3
import ssl

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Modify SSL context globally
ssl._create_default_https_context = ssl._create_unverified_context
def connect_timesketch_api():
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Extract Timesketch credentials from the configuration
    try:
        host_uri = f"https://localhost"  # Ensure the URL is correctly formatted
        username = "10admin"
        password = "m1JNctOc6JrCKcuf9bB8LtpmhCx9vxDr"

        # Initialize the Timesketch API client with SSL verification disabled
        api = client.TimesketchApi(
            host_uri=host_uri,
            username=username,
            password=password,
            verify=False  # Disable SSL certificate verification
        )
        print("TimeSketch api connected!")
        return api
    except Exception as e:
        print(f"Error: Missing key {e} in configuration file.")
        return None

api = connect_timesketch_api()
sketch_list = api.list_sketches()
for sketch in sketch_list:
    print(sketch.id)
print(sketch_list)
sketch = api.get_sketch(15)
print(sketch)
timelines = sketch.list_timelines()
print(timelines)
