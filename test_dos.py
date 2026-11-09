import requests
import time
from concurrent.futures import ThreadPoolExecutor

API_URL = "http://127.0.0.1:8000/api/predict"
HEALTH_URL = "http://127.0.0.1:8000/api/health"

# generate session UUID with [guid]::NewGuid() on Terminal (when its running)
# then replace the string in SESSION_ID with that
SESSION_ID = "38102daf-50bd-4ae4-8cb2-3c22c7b34433"


def send_request(number, slow=False):
    headers = {
        "Content-Type": "application/json",
        "X-Session-ID": SESSION_ID
    }

    if slow:
        headers["X-Test-Slow"] = "true"

    data = {
        "url": f"https://example.com/test{number}"
    }

    start = time.perf_counter()

    try:
        response = requests.post(
            API_URL,
            headers=headers,
            json=data,
            timeout=10
        )

        elapsed = time.perf_counter() - start

        return response.status_code, elapsed

    except requests.RequestException as error:
        return str(error), 0


# test 1: slow req

print("\nTEST 1")
print("Starting 1 slow request:")

with ThreadPoolExecutor(max_workers=2) as executor:
    slow_future = executor.submit(send_request, 1, True)
    time.sleep(0.3)

    # send normal req while slow req is running
    print("Sending a normal request...")

    normal_status, normal_time = send_request(2, False)
    slow_status, slow_time = slow_future.result()

print(f"\nSlow request: HTTP {slow_status}, {slow_time:.2f} seconds")
print(f"Normal request: HTTP {normal_status}, {normal_time:.2f} seconds")

# test 2: many slow reqs simultaneously

print("\nTEST 2")
print("20 slow requests simultaneously:")

with ThreadPoolExecutor(max_workers=20) as executor:
    futures = [
        executor.submit(send_request, i, True)
        for i in range(20)
    ]
    results = [future.result() for future in futures]

print("\nRequest results:")

for status in sorted(set(str(result[0]) for result in results)):
    count = sum(str(result[0]) == status for result in results)
    print(f"HTTP {status}: {count} requests")

# test 3: server health and response check

print("\nTEST 3")
print("Checking server health:")

try:
    health = requests.get(HEALTH_URL, timeout=5)

    print("Health check status:", health.status_code)
    print("Health response:", health.text)

except requests.RequestException as error:
    print("Health check failed:", error)