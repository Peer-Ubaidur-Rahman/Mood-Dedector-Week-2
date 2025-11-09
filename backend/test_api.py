import requests
import json

BASE_URL = "http://localhost:5000/api"

def print_response(title, response):
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

print("\n🧪 Testing API Endpoints...")
response = requests.get(f"{BASE_URL}/health")
print_response("1. Health Check", response)

signup_data = {
    "fullname": "Test User",
    "email": "test@example.com",
    "password": "testpassword123"
}
response = requests.post(f"{BASE_URL}/signup", json=signup_data)
print_response("2. Sign Up", response)

login_data = {
    "email": "test@example.com",
    "password": "testpassword123"
}
response = requests.post(f"{BASE_URL}/login", json=login_data)
print_response("3. Login", response)

if response.status_code == 200:
    token = response.json()['token']
    user_id = response.json()['user']['id']
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.get(f"{BASE_URL}/users/{user_id}", headers=headers)
    print_response("4. Get User Profile", response)
    
    mood_data = {
        "emotion": "happy",
        "confidence": 0.89
    }
    response = requests.post(f"{BASE_URL}/mood-records", json=mood_data, headers=headers)
    print_response("5. Create Mood Record", response)
    
    response = requests.get(f"{BASE_URL}/mood-records", headers=headers)
    print_response("6. Get All Mood Records", response)
    
    response = requests.post(f"{BASE_URL}/sessions", headers=headers)
    print_response("7. Start Session", response)
    
    if response.status_code == 201:
        session_id = response.json()['session_id']
        
        session_data = {
            "emotions_detected": 10,
            "end_session": True
        }
        response = requests.put(f"{BASE_URL}/sessions/{session_id}", json=session_data, headers=headers)
        print_response("8. Update Session", response)
    
    response = requests.get(f"{BASE_URL}/sessions", headers=headers)
    print_response("9. Get All Sessions", response)
    
    response = requests.get(f"{BASE_URL}/stats/emotions", headers=headers)
    print_response("10. Get Emotion Statistics", response)

print("\n✅ Testing Complete!")
