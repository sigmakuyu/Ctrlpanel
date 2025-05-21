# pterodactyl.py
import requests
import logging

# Konfigurasi Pterodactyl Panel API
PTERODACTYL_URL = "https://panel.kocheng.biz.id"
PTERODACTYL_API_KEY = "ptla_hApYLXfqCJS0bhPDUGk93LeayUFZspT0JGmAf5jgx5A"

# Header API
headers = {
    "Authorization": f"Bearer {PTERODACTYL_API_KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

url = f"{PTERODACTYL_URL}/api/application/nests/5/eggs/{15}"
response = requests.get(url, headers=headers)
response.raise_for_status()
data2 = response.json()

if 'attributes' not in data2:
    logging.error(f"Response JSON tidak mengandung 'attributes': {data2}")
    startup_cmd = ""
else:
    startup_cmd = data2['attributes']['startup']

def get_available_allocation(NODE_ID):
    page = 1
    while True:
        url = f"{PTERODACTYL_URL}/api/application/nodes/{NODE_ID}/allocations?page={page}"
        response = requests.get(url, headers=headers)
        data = response.json()

        for alloc in data['data']:
            if not alloc['attributes']['assigned']:
                return alloc['attributes']['id']

        # Jika tidak ada halaman berikutnya, berhenti
        if not data['meta']['pagination']['links']['next']:
            break

        page += 1

    return None    

# Fungsi buat user (jika belum ada)
def create_user(email, username):
    try:
        # Cek apakah user sudah ada berdasarkan email
        check_response = requests.get(
            f"{PTERODACTYL_URL}/api/application/users?filter[email]={email}",
            headers=headers
        )
        check_response.raise_for_status()
        data = check_response.json()

        if data["data"]:  # Email sudah terdaftar
            user_id = data["data"][0]["attributes"]["id"]
            logging.info(f"User already exists: ID {user_id}")
            return {"id": user_id}  # Langsung return user ID

        # Kalau belum ada, buat user baru
        user_data = {
            "email": email,
            "username": username,
            "first_name": username,
            "last_name": "User",
            "password": username,
        }
        logging.info(f"Creating new user: {user_data}")
        response = requests.post(
            f"{PTERODACTYL_URL}/api/application/users",
            json=user_data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        error_message = f"Error creating Pterodactyl user: {str(e)}"
        if e.response is not None:
            error_message += f", Response: {e.response.text}"
        logging.error(error_message)
        return None


# Fungsi buat server
def create_server(user_id, name, egg_id, node_id, cpu, ram, disk):
    try:
        allocation_id = get_available_allocation(node_id)
        if allocation_id is None:
            logging.error("Tidak ada allocation ID yang tersedia.")
            return None

        server_data = {
            "name": name,
            "user": user_id,
            "egg": 15,
            "docker_image": "ghcr.io/parkervcp/yolks:nodejs_18",
            "startup": startup_cmd,
            "environment": {
                "NODE_VERSION": "18",
                "CMD_RUN": "npm start"
            },
            "limits": {
                "memory": ram,       # RAM dalam MB (misal: 1024)
                "swap": 0,
                "disk": disk,        # Disk dalam MB (misal: 1024)
                "io": 500,
                "cpu": cpu           # CPU dalam persen (misal: 100)
            },
            "feature_limits": {
                "databases": 5,
                "backups": 1
            },
            "allocation": {
                "default": allocation_id
            },
            "description": "Free"
        }

        logging.info(f"Sending request to create server for user_id {user_id}: {server_data}")
        response = requests.post(f"{PTERODACTYL_URL}/api/application/servers", json=server_data, headers=headers)
        response.raise_for_status()
        logging.info(f"Pterodactyl server creation response: {response.json()}")
        return response.json()
    except requests.exceptions.RequestException as e:
        error_message = f"Error creating Pterodactyl server for user_id_order {user_id}: {str(e)}"
        if e.response is not None:
            error_message += f", Response: {e.response.text}"
        logging.error(error_message)
        return None
        