import requests
from time import sleep
import os
import base64
import time

# Define login credentials
login_data = {
    'isTest': 'false',
    'goformId': 'LOGIN',
    'password': 'YWRtaW4='  # Base64 encoded password
}

# Define query parameters for various requests
params = {
    'isTest': 'false',
    'cmd': 'station_list',
    '_': '1706720640677'
}

blacklist_params = {
    'isTest': 'false',
    'multi_data': '1',
    'cmd': 'ACL_mode,wifi_mac_black_list,wifi_hostname_black_list,RadioOff,user_ip_addr',
    '_': '1706738310672'
}

# Define URL endpoints
base_url = 'http://192.168.0.1/goform/goform_set_cmd_process'
station_list_url = 'http://192.168.0.1/goform/goform_get_cmd_process'
current_blacklist_url = 'http://192.168.0.1/goform/goform_get_cmd_process'

# Define headers for requests
common_headers = {
    'Host': '192.168.0.1',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Accept-Language': 'en-US,en;q=0.9',
    'X-Requested-With': 'XMLHttpRequest'
}

# Define the GET request parameters
get_params = {
    'isTest': 'false',
    'multi_data': '1',
    'cmd': 'ACL_mode,wifi_mac_black_list,wifi_hostname_black_list',
    '_': '1706738310672'
}

login_headers = common_headers.copy()
login_headers.update({
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Origin': base_url,
    'Referer': 'http://192.168.0.1/index.html'
})

session_headers = common_headers.copy()
session_headers.update({
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Origin': base_url,
    'Referer': 'http://192.168.0.1/index.html'
})

# Function to login and process station list
def login_and_process_station_list():
    # Send POST request for login
    requests.post(base_url, headers=login_headers, data=login_data)
    sleep(1)

    # Get station list
    response = requests.get(station_list_url, params=params, headers=session_headers)
    if response.status_code == 200:
        station_data = response.json().get('station_list', [])
        return station_data
    return []

# Function to save blacklist to a file
def save_blacklist_to_file(mac_black_list, hostname_black_list):
    with open('black.txt', 'w') as file:
        file.write(f'Hostname Blacklist: {";".join(hostname_black_list)}\n')
        file.write(f'MAC Blacklist: {";".join(mac_black_list)}\n')

        max_len = max(len(mac_black_list), len(hostname_black_list))
        file.write("\r\n")
        file.write("_____________________Black_List__________________\r\n")
        for i in range(max_len):
            mac = mac_black_list[i].strip() if i < len(mac_black_list) else ''
            hostname = hostname_black_list[i].strip() if i < len(hostname_black_list) else ''
            output_line = f"{i+1:2d}: |{hostname:20s}| {mac:20s} |"
            file.write(output_line + '\n')
            
            print(output_line)

    #print("Blacklist saved to black.txt")

# Function to get current blacklist
def get_current_black_list():
    response = requests.get(current_blacklist_url, params=blacklist_params, headers=session_headers)
    if response.status_code == 200:
        data = response.json()
        mac_list = data.get('wifi_mac_black_list', '').split(';')
        hostname_list = data.get('wifi_hostname_black_list', '').split(';')
        save_blacklist_to_file(mac_list, hostname_list)

# Function to send network connection request
def send_network_connection_request():
    response = requests.post(base_url, headers=session_headers, data={'isTest': 'false', 'notCallback': 'true', 'goformId': 'CONNECT_NETWORK'})
    print(response.text)

# Function to send network disconnection request
def send_disconnect_network_request():
    response = requests.post(base_url, headers=session_headers, data={'isTest': 'false', 'notCallback': 'true', 'goformId': 'DISCONNECT_NETWORK'})
    print(response.text)

# Function to get station MAC addresses
def get_station_mac_addresses():
    response = requests.get(station_list_url, params={'multi_data': '1', 'isTest': 'false', 'cmd': 'station_mac', '_': '1706720640959'}, headers=session_headers)
    if response.status_code == 200:
        mac_addresses = response.json().get('station_mac', '').split(';')
        for index, mac_address in enumerate(mac_addresses, start=1):
            mac_address = mac_address.strip()
            if mac_address:
                print(f"{index}: | {mac_address} |")

# Function to clear console screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to send Wi-Fi settings
def send_wifi_settings(ssid, password):
    encoded_password = base64.b64encode(password.encode()).decode()
    data = {
        'goformId': 'SET_WIFI_SSID1_SETTINGS',
        'isTest': 'false',
        'ssid': ssid,
        'broadcastSsidEnabled': '0',
        'MAX_Access_num': '32',
        'security_mode': 'WPA2PSK',
        'cipher': '1',
        'NoForwarding': '0',
        'security_shared_mode': '1',
        'passphrase': encoded_password,
    }
    response = requests.post(base_url, headers=session_headers, data=data)
    return response.text

# Function to reboot device
def reboot_device():
    response = requests.post(base_url, headers=session_headers, data={'isTest': 'false', 'goformId': 'REBOOT_DEVICE'})
    print(response.text)

# Function to log out
def logout():
    response = requests.post(base_url, headers=session_headers, data={'isTest': 'false', 'goformId': 'LOGOUT'})
    return response.text

# Function to restore factory settings
def restore_factory_settings():
    response = requests.post(base_url, headers=session_headers, data={'isTest': 'false', 'goformId': 'RESTORE_FACTORY_SETTINGS'})
    print(response.text)

# Function to update blacklists
def update_blacklists(new_hostname_devices, new_mac_devices):
    response = requests.get(current_blacklist_url, params=blacklist_params, headers=session_headers)
    if response.status_code == 200:
        blacklist_data = response.json()
        mac_black_list = blacklist_data.get('wifi_mac_black_list', '').split(';')
        hostname_black_list = blacklist_data.get('wifi_hostname_black_list', '').split(';')

        new_hostname_devices = [device.strip() for device in new_hostname_devices if device.strip()]
        new_mac_devices = [device.strip() for device in new_mac_devices if device.strip()]

        hostname_black_list[:0] = new_hostname_devices
        mac_black_list[:0] = new_mac_devices

        data = {
            'goformId': 'WIFI_MAC_FILTER',
            'isTest': 'false',
            'ACL_mode': '2',
            'macFilteringMode': '2',
            'wifi_hostname_black_list': ';'.join(hostname_black_list),
            'wifi_mac_black_list': ';'.join(mac_black_list),
        }

        response = requests.post(base_url, headers=session_headers, data=data)
        print(response.text)
        save_blacklist_to_file(mac_black_list, hostname_black_list)

# Function to get speeds
def get_speeds():
    url = 'http://192.168.0.1/goform/goform_get_cmd_process'
    params = {
        'multi_data': '1',
        'isTest': 'false',
        'cmd': 'realtime_tx_thrpt,realtime_rx_thrpt',
        '_': '1706814613926'
    }
    response = requests.get(url, params=params, headers=session_headers)

    if response.status_code == 200:
        data = response.json()
        upload_speed_byte = int(data["realtime_tx_thrpt"])
        download_speed_byte = int(data["realtime_rx_thrpt"])

        # Convert to kilobits per second (kb/s)
        upload_speed_kb = upload_speed_byte * 8 / 1000
        download_speed_kb = download_speed_byte * 8 / 1000

        # Convert to megabits per second (Mb/s) if speed exceeds 499 kb/s
        if upload_speed_kb > 499:
            upload_speed_mb = upload_speed_kb / 1000
            upload_speed = "{:.2f} Mb/s".format(upload_speed_mb)
        else:
            upload_speed = "{:.2f} Kb/s".format(upload_speed_kb)

        if download_speed_kb > 499:
            download_speed_mb = download_speed_kb / 1000
            download_speed = "{:.2f} Mb/s".format(download_speed_mb)
        else:
            download_speed = "{:.2f} Kb/s".format(download_speed_kb)

        #return upload_speed, download_speed
        print("Upload:", upload_speed)
        print("Download:", download_speed)
    else:
        return "Failed to retrieve data. Status code:", response.status_code

def add_custom_blacklist():
    # Define the URLs
    get_url = 'http://192.168.0.1/goform/goform_get_cmd_process'
    set_url = 'http://192.168.0.1/goform/goform_set_cmd_process'

    # Send the GET request to fetch current blacklists
    response = requests.get(get_url, params=get_params, headers=session_headers)

    # Parse the response content into a dictionary
    data = {}
    if response.status_code == 200:
        # Assuming the response content is in JSON format
        response_json = response.json()
        for key, value in response_json.items():
            data[key] = value

    # Extract blacklisted MAC addresses and hostnames
    mac_black_list = data.get('wifi_mac_black_list', '').split(';')
    hostname_black_list = data.get('wifi_hostname_black_list', '').split(';')

    # Prompt the user to input new devices
    new_hostname_devices_input = input("Enter new hostnames separated by commas (,): ")
    new_mac_devices_input = input("Enter new MAC addresses separated by commas (,): ")

    # Split the input into individual devices
    new_hostname_devices = [device.strip() for device in new_hostname_devices_input.split(',') if device.strip()]
    new_mac_devices = [device.strip() for device in new_mac_devices_input.split(',') if device.strip()]

    # Update blacklists
    hostname_black_list[:0] = new_hostname_devices
    mac_black_list[:0] = new_mac_devices

    # Define the POST request parameters
    set_params = {
        'goformId': 'WIFI_MAC_FILTER',
        'isTest': 'false',
        'ACL_mode': '2',
        'macFilteringMode': '2',
        'wifi_hostname_black_list': ';'.join(hostname_black_list),
        'wifi_mac_black_list': ';'.join(mac_black_list),
    }

    # Send the POST request to update blacklists
    response = requests.post(set_url, headers=session_headers, data=set_params)

    # Print the response
    print(response.text)

    # Save the updated blacklists to black.txt
    save_blacklist_to_file(mac_black_list, hostname_black_list)

def remove_custom_blacklist():
    # Define the URLs
    get_url = 'http://192.168.0.1/goform/goform_get_cmd_process'
    set_url = 'http://192.168.0.1/goform/goform_set_cmd_process'

    # Send the GET request to fetch current blacklists
    response = requests.get(get_url, params=get_params, headers=session_headers)

    # Parse the response content into a dictionary
    data = {}
    if response.status_code == 200:
        # Assuming the response content is in JSON format
        response_json = response.json()
        for key, value in response_json.items():
            data[key] = value

    # Extract blacklisted MAC addresses and hostnames
    mac_black_list = data.get('wifi_mac_black_list', '').split(';')
    hostname_black_list = data.get('wifi_hostname_black_list', '').split(';')

    # Display the current blacklists with their IDs
    print("Current Blacklists:")
    for i in range(len(mac_black_list)):
        print(f"{i+1}: |{hostname_black_list[i]:20s}| {mac_black_list[i]:20s} |")

    # Prompt the user to input the IDs of the entries to remove
    entry_ids_input = input("Enter IDs to unblock (separated by commas): ")

    # Split the input into individual IDs
    entry_ids = [int(id.strip()) for id in entry_ids_input.split(',') if id.strip()]

    # Remove the entries corresponding to the provided IDs
    for entry_id in entry_ids:
        if 1 <= entry_id <= len(mac_black_list):
            del mac_black_list[entry_id - 1]
            del hostname_black_list[entry_id - 1]
        else:
            print(f"Invalid entry ID: {entry_id}")

    # Define the POST request parameters
    set_params = {
        'goformId': 'WIFI_MAC_FILTER',
        'isTest': 'false',
        'ACL_mode': '2',
        'macFilteringMode': '2',
        'wifi_hostname_black_list': ';'.join(hostname_black_list),
        'wifi_mac_black_list': ';'.join(mac_black_list),
    }

    # Send the POST request to update blacklists
    response = requests.post(set_url, headers=session_headers, data=set_params)

    # Print the response
    print(response.text)

    # Save the updated blacklists to black.txt
    save_blacklist_to_file(mac_black_list, hostname_black_list)

station_data = []

station_data = login_and_process_station_list()
for index, entry in enumerate(station_data, start=1):
    mac_addr = entry.get('mac_addr', '')
    hostname = entry.get('hostname', '')[:32]
    ip_addr = entry.get('ip_addr', '')

    # Format and print station information
    print(f"{index}: |{mac_addr:<17} | {hostname:<32} |{ip_addr:<13}|")        
while True:
    option = input("Choose an option: block_id, block_custom, unblock, blist, logout, login, connect, disconect, speed, reboot, reset, get_mac, set_wifi or exit: ").strip().lower()

    if option == "login":
        station_data = login_and_process_station_list()
        for index, entry in enumerate(station_data, start=1):
            mac_addr = entry.get('mac_addr', '')
            hostname = entry.get('hostname', '')[:32]
            ip_addr = entry.get('ip_addr', '')

            # Format and print station information
            print(f"{index}: |{mac_addr:<17} | {hostname:<32} |{ip_addr:<13}|")

    elif option == "block_id":
        selected_ids = input("Enter IDs to block (separated by commas): ").split(',')
        # Block selected IDs by adding their hostnames and MAC addresses to blacklists
        new_hostname_devices = [station_data[int(id) - 1]['hostname'] for id in selected_ids]
        new_mac_devices = [station_data[int(id) - 1]['mac_addr'] for id in selected_ids]

        update_blacklists(new_hostname_devices, new_mac_devices)

    elif option == "block_custom":
        add_custom_blacklist()
    elif option == "unblock":
        remove_custom_blacklist()
    elif option == "logout":
        logout()
    elif option == "login":
        login_and_process_station_list()  
    elif option == "connect":
        send_network_connection_request()   
    elif option == "disconect":
        send_disconnect_network_request()
    elif option == "speed":
        end_time = time.time() + 10
        while time.time() < end_time:
            get_speeds()
            sleep(1)
    elif option == "reboot":
        reboot_device() 
    elif option == "reset":
        restore_factory_settings()  
    elif option == "get_mac":
        get_station_mac_addresses()
    elif option == "blist":
        get_current_black_list()
    elif option == "clear":
        clear_screen()
    elif option == "set_wifi":
        ssid = input("Enter the Wi-Fi SSID: ")
        password = input("Enter the Wi-Fi Password: ")
        response = send_wifi_settings(ssid, password)
        print(response)
    elif option == "exit":
        print("Exiting...")
        break
        
    else:
        print("Invalid option. Please choose again.")


