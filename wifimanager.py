# wifimanager.py
# Modified WifiManager: captive DNS + redirect probe handling + XOR Hardware Encryption
# Author: adapted from Igor Ferreira, modifications by Gemini
# License: MIT

import machine
import network
import socket
import re
import time
import _thread

green_led = machine.Pin(33, machine.Pin.OUT)

class WifiManager:
    def __init__(self, ssid='WifiManager', password='', reboot=True, debug=False):
        # STA + AP interfaces
        self.wlan_sta = network.WLAN(network.STA_IF)
        self.wlan_sta.active(True)
        self.wlan_ap = network.WLAN(network.AP_IF)

        # AP settings
        if len(ssid) > 32:
            raise Exception('The SSID cannot be longer than 32 characters.')
        self.ap_ssid = ssid

        # allow open AP when password is empty
        if password is None:
            password = ''
        if password != '':
            if len(password) < 8:
                raise Exception('The password cannot be less than 8 characters long.')
            self.ap_password = password
            self.ap_authmode = 3  # WPA2
        else:
            self.ap_password = ''
            self.ap_authmode = 0  # open

        # credentials storage (using .dat for binary encrypted data)
        self.wifi_credentials = 'wifi.dat'

        # prevent auto connect until we explicitly do so
        try:
            self.wlan_sta.disconnect()
        except:
            pass

        self.reboot = reboot
        self.debug = debug
        self.new_credentials_to_try = None # Store pending connection attempts

        # AP network configuration (explicit IP)
        self.ap_ip = '192.168.4.1'
        self.ap_netmask = '255.255.255.0'
        self.ap_gateway = self.ap_ip
        self.ap_dns = self.ap_ip

        # Initialize AP with SSID/password
        try:
            self.wlan_ap.config(essid=self.ap_ssid, password=self.ap_password, authmode=self.ap_authmode)
            self.wlan_ap.ifconfig((self.ap_ip, self.ap_netmask, self.ap_gateway, self.ap_dns))
            self.wlan_ap.active(False)
        except Exception as e:
            if self.debug:
                print("[wm] AP init failed:", e)

    # -----------------
    # XOR Encryption Helpers
    # -----------------
    def _xor_crypt(self, data):
        """Encrypts/Decrypts data using the ESP32's unique hardware ID."""
        key = machine.unique_id()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def write_credentials(self, profiles):
        """Encrypts and writes credentials as binary data."""
        try:
            with open(self.wifi_credentials, 'wb') as f:
                for ssid, password in profiles.items():
                    # Format as bytes, then XOR
                    plain_line = '{0};{1}\n'.format(ssid, password).encode('utf-8')
                    encrypted_line = self._xor_crypt(plain_line)
                    
                    # Store block length (1 byte) followed by the encrypted data
                    f.write(bytes([len(encrypted_line)]))
                    f.write(encrypted_line)
            if self.debug:
                print("[wm] Encrypted credentials saved.")
        except Exception as e:
            print("[wm] Error saving credentials:", e)

    def read_credentials(self):
        """Reads binary data and decrypts it using the hardware key."""
        profiles = {}
        try:
            with open(self.wifi_credentials, 'rb') as f:
                while True:
                    length_byte = f.read(1)
                    if not length_byte:
                        break
                    
                    length = length_byte[0]
                    encrypted_data = f.read(length)
                    
                    # Decrypt and turn back into a string
                    decrypted_line = self._xor_crypt(encrypted_data).decode('utf-8')
                    
                    try:
                        ssid, password = decrypted_line.strip().split(';')
                        profiles[ssid] = password
                    except:
                        continue
        except Exception as e:
            if self.debug:
                print("[wm] No credentials found or read error:", e)
        return profiles

    # -----------------
    # DNS server thread to answer all queries with AP IP
    # -----------------
    def start_dns(self):
        def dns_thread(ap_ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', 53))
                if self.debug:
                    print("[dns] started on UDP/53")
            except Exception as e:
                if self.debug:
                    print("[dns] failed to bind:", e)
                return

            while True:
                try:
                    data, addr = sock.recvfrom(512)
                    if not data:
                        continue
                    dns_id = data[:2]
                    flags = b'\x81\x80'
                    qdcount = data[4:6]
                    ancount = qdcount
                    nscount = b'\x00\x00'
                    arcount = b'\x00\x00'
                    query = data[12:]
                    try:
                        rdata = bytes(map(int, ap_ip.split('.')))
                    except:
                        rdata = b'\xc0\xa8\x01\x01' # Fallback 192.168.1.1
                    answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + rdata
                    response = dns_id + flags + qdcount + ancount + nscount + arcount + query + answer
                    sock.sendto(response, addr)
                except Exception:
                    continue

        try:
            _thread.start_new_thread(dns_thread, (self.ap_ip,))
            if self.debug:
                print("[dns] thread started")
        except Exception as e:
            if self.debug:
                print("[dns] thread start failed:", e)

    # -----------------
    # Try to connect to saved networks; otherwise start portal
    # -----------------
    def connect(self):
        if self.wlan_sta.isconnected():
            if self.debug:
                print("[wm] already connected")
            return

        profiles = self.read_credentials()
        try:
            scans = list(self.wlan_sta.scan())
        except Exception:
            scans = []

        for ssid, *_ in scans:
            ssid = ssid.decode("utf-8")
            if ssid in profiles:
                password = profiles[ssid]
                if self.wifi_connect(ssid, password):
                    return

        print('Could not connect to any WiFi network. Starting the configuration portal...')
        self.start_dns()
        self.web_server()

    def disconnect(self):
        if self.wlan_sta.isconnected():
            self.wlan_sta.disconnect()

    def is_connected(self):
        return self.wlan_sta.isconnected()

    def get_address(self):
        return self.wlan_sta.ifconfig()

    def wifi_connect(self, ssid, password):
        print('Trying to connect to:', ssid)
        try:
            self.wlan_sta.connect(ssid, password)
        except Exception as e:
            if self.debug:
                print("[wm] wlan_sta.connect error:", e)
        for _ in range(100):
            if self.wlan_sta.isconnected():
                print('\nConnected! Network information:', self.wlan_sta.ifconfig())

                # Visual indicator for end user that connection is successful
                green_led.value(1)
                time.sleep(0.5)
                green_led.value(0)
                time.sleep(0.5)
                green_led.value(1)
                time.sleep(0.5)
                green_led.value(0)

                return True
            else:
                try:
                    print('.', end='')
                except:
                    pass
                time.sleep_ms(100)
        print('\nConnection failed!')
        try:
            self.wlan_sta.disconnect()
        except:
            pass
        return False

    # -----------------
    # Web server (captive portal)
    # -----------------
    def web_server(self):

        try:
            self.wlan_ap.active(True)
            self.wlan_ap.config(essid=self.ap_ssid, password=self.ap_password, authmode=self.ap_authmode)
            self.wlan_ap.ifconfig((self.ap_ip, self.ap_netmask, self.ap_gateway, self.ap_dns))
            time.sleep_ms(200)
            self.wlan_ap.active(True)
        except Exception as e:
            if self.debug:
                print("[wm] ap.active(True) failed:", e)

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('', 80))
            server_socket.listen(1)
        except Exception as e:
            if self.debug:
                print("[wm] server socket setup failed:", e)
            return

        print('Connect to', self.ap_ssid, 'and open the captive portal at', self.ap_ip)

        while True:
            try:
                if self.wlan_sta.isconnected():
                    try:
                        self.wlan_ap.active(False)
                    except:
                        pass
                    if self.reboot:
                        print('The device will reboot in 5 seconds.')
                        time.sleep(5)
                        machine.reset()
                    else:
                        break # Exit portal loop
            except Exception:
                pass

            if self.new_credentials_to_try:
                ssid, password = self.new_credentials_to_try
                self.new_credentials_to_try = None 
                connected = self.wifi_connect(ssid, password)

                if connected:
                    print(f"Successfully connected to {ssid}. Saving credentials.")
                    profiles = self.read_credentials()
                    profiles[ssid] = password
                    self.write_credentials(profiles)
                else:
                    print(f"Connection to {ssid} failed. Restarting AP for re-configuration.")
                    time.sleep(1) 
                continue 

            try:
                client, addr = server_socket.accept()
            except Exception as e:
                if self.debug:
                    print("[wm] accept failed:", e)
                continue

            try:
                client.settimeout(5.0)
                request = b''
                try:
                    while True:
                        chunk = client.recv(512)
                        if not chunk:
                            break
                        request += chunk
                        if b'\r\n\r\n' in request:
                            try:
                                request += client.recv(512)
                            except:
                                pass
                            break
                except Exception as err:
                    if self.debug:
                        print("[wm] recv loop error:", err)

                if not request:
                    try:
                        client.close()
                    except:
                        pass
                    continue

                try:
                    req_text = request.decode('utf-8', errors='ignore')
                except:
                    req_text = str(request)
                if self.debug:
                    print("[wm] REQ:\n", req_text)

                if "captive.apple.com" in req_text or "generate_204" in req_text or "connectivitycheck" in req_text:
                    self._send_redirect(client, "http://{}/".format(self.ap_ip))
                    continue

                try:
                    m = re.search(b'(?:GET|POST) /(.*?)(?:\\?.*?)? HTTP', request)
                    if m:
                        url = m.group(1).decode('utf-8').rstrip('/')
                    else:
                        url = ''
                except Exception:
                    url = ''

                if url == '':
                    self._handle_root(client)
                elif url == 'configure':
                    self._handle_configure(client, request)
                else:
                    self._handle_not_found(client)

            except Exception as error:
                if self.debug:
                    print("[wm] main handler error:", error)
            finally:
                try:
                    client.close()
                except:
                    pass

    # -----------------
    # HTTP helpers
    # -----------------
    def _send_header(self, client, status_code=200, content_type='text/html', content_length=None):
        try:
            client.send("HTTP/1.1 {0} OK\r\n".format(status_code))
            client.send("Content-Type: {}\r\n".format(content_type))
            if content_length is not None:
                client.send("Content-Length: {}\r\n".format(content_length))
            client.send("Connection: close\r\n\r\n")
        except:
            pass

    def _send_response(self, client, payload, status_code=200):
        if isinstance(payload, str):
            body = payload
        else:
            body = str(payload)
        body_bytes = body.encode('utf-8')
        self._send_header(client, status_code=status_code, content_length=len(body_bytes))
        try:
            client.sendall(body_bytes)
        except:
            pass
        try:
            client.close()
        except:
            pass

    def _send_redirect(self, client, location):
        try:
            client.send("HTTP/1.1 302 Found\r\n")
            client.send("Location: {}\r\n".format(location))
            client.send("Connection: close\r\n\r\n")
        except:
            pass
        try:
            client.close()
        except:
            pass

    # -----------------
    # Portal pages
    # -----------------
    def _handle_root(self, client):
        body = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ESP32 Wi-Fi Setup</title>
<style>
    body {
        font-family: -apple-system, system-ui, sans-serif;
        background-color: #1a1a1a; /* Dark background */
        color: #f0f0f0; /* Light text */
        margin: 0;
        padding: 20px;
        display: flex;
        flex-direction: column;
        align-items: center;
        min-height: 100vh; /* Ensure full viewport height */
        box-sizing: border-box;
    }
    .container {
        width: 90%;
        max-width: 400px;
        margin-top: 50px; /* Space from top */
        padding: 20px;
        border-radius: 8px;
        text-align: center;
    }
    h1 {
        color: #f0f0f0;
        font-size: 24px;
        margin-bottom: 25px;
    }
    form {
        display: flex;
        flex-direction: column;
        align-items: center; /* Center form elements */
    }
    .ssid-list-box {
        background-color: #4a4a4a; /* Grey background for the box */
        border-radius: 8px;
        width: 100%;
        min-height: 150px; /* Minimum height for the rectangle */
        max-height: 250px; /* Max height for scroll */
        overflow-y: auto;
        margin-bottom: 20px;
        padding: 10px; /* Padding inside the box */
        box-sizing: border-box;
        border: 1px solid #666; /* Slightly lighter border */
    }
    .network-item {
        margin-bottom: 5px;
        text-align: left; /* Align network names to the left */
    }
    .network-item label {
        display: block;
        padding: 8px 10px;
        color: #f0f0f0;
        cursor: pointer;
        border-radius: 4px;
        transition: background-color 0.2s;
    }
    .network-item input[type="radio"] {
        display: none; /* Hide default radio button */
    }
    .network-item input[type="radio"]:checked + label {
        background-color: #007aff; /* Highlight selected network */
        color: #fff;
    }
    .network-item label:hover {
        background-color: #6a6a6a; /* Hover effect */
    }
    input[type="password"] {
        width: 100%;
        max-width: 300px; /* Max width for password input */
        padding: 12px;
        margin-bottom: 25px;
        background-color: #333; /* Darker input background */
        color: #f0f0f0;
        border: 1px solid #555;
        border-radius: 5px;
        box-sizing: border-box;
        font-size: 16px;
        text-align: center; /* Center placeholder text */
    }
    input[type="submit"] {
        width: 150px; /* Fixed width for submit button */
        padding: 12px;
        background-color: #007aff; /* Blue submit button */
        color: white;
        font-weight: bold;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        font-size: 16px;
        transition: background-color 0.2s;
    }
    input[type="submit"]:hover {
        background-color: #0056b3;
    }
    /* Placeholder color for dark theme */
    input[type="password"]::placeholder {
        color: #aaa;
        opacity: 1; /* Firefox fix */
    }
</style>
</head>
<body>
<div class="container">
    <h1>Available WiFi Networks</h1>

    <form action="/configure" method="get">
        <div class="ssid-list-box">
"""
        try:
            networks = []
            for ssid, *_ in self.wlan_sta.scan():
                networks.append(ssid.decode("utf-8"))
            if not networks:
                 body += "<p style='text-align: center; color: #aaa;'>No networks found.<br>Scanning...</p>"
            networks.sort()
            for ssid in networks:
                body += '<div class="network-item"><input type="radio" name="ssid" value="{0}" id="{0}"><label for="{0}">{0}</label></div>\n'.format(ssid)
        except Exception:
            body += "<p style='text-align: center; color: #aaa;'>Error scanning networks.</p>"

        body += """
        </div>
        <input type="password" name="password" placeholder="Enter password...">
        <input type="submit" value="Submit">
    </form>
</div>
</body>
</html>
"""
        self._send_response(client, body)

    def _handle_configure(self, client, request_bytes):
        try:
            decoded = self.url_decode(request_bytes)
            match = re.search(b"ssid=([^&]*)&password=([^& ]*)", decoded)
            if match:
                try:
                    ssid = match.group(1).decode("utf-8")
                except:
                    ssid = ""
                try:
                    password = match.group(2).decode("utf-8")
                except:
                    password = ""

                if len(ssid) == 0:
                    self._send_response(client, "<p>SSID must be provided!</p>", status_code=400)
                    return

                self.new_credentials_to_try = (ssid, password)

                body = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="7; url=/">
<title>Connecting...</title>
<style>
    body {{
        font-family: -apple-system, system-ui, sans-serif;
        background-color: #1a1a1a;
        color: #f0f0f0;
        margin: 0;
        padding: 20px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: flex-start;
        min-height: 100vh;
        box-sizing: border-box;
        text-align: center;
        padding-top: 50px;
    }}
    h1 {{
        color: #f0f0f0;
        font-size: 24px;
        margin-bottom: 15px;
    }}
    p {{
        font-size: 16px;
        color: #aaa;
        margin: 5px 0;
    }}
    strong {{
        color: #007aff;
    }}
    .spinner {{
        border: 4px solid rgba(255, 255, 255, 0.2);
        border-left-color: #007aff;
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 30px auto;
    }}
    @keyframes spin {{
        to {{ transform: rotate(360deg); }}
    }}
</style>
</head>
<body>
    <h1>Attempting to Connect</h1>
    <div class="spinner"></div>
    <p>Trying to connect to network:</p>
    <p><strong>{0}</strong></p>
    <p style="font-size: 12px; margin-top: 20px;">If connection fails, this page will reload.</p>
</body>
</html>""".format(ssid)
                self._send_response(client, body)
                return
            else:
                self._send_response(client, "<p>Parameters not found!</p>", status_code=400)
                time.sleep(2)
                return
        except Exception as e:
            if self.debug:
                print("[wm] handle_configure error:", e)
            try:
                self._send_response(client, "<p>Server error</p>", status_code=500)
            except:
                pass
            time.sleep(2)

    def _handle_not_found(self, client):
        self._send_response(client, "<p>Page not found!</p>", status_code=404)

    def url_decode(self, url_string):
        if not url_string:
            return b''
        if isinstance(url_string, str):
            url_string = url_string.encode('utf-8')
        url_string = url_string.replace(b'+', b' ')
        bits = url_string.split(b'%')
        if len(bits) == 1:
            return url_string
        res = [bits[0]]
        appnd = res.append
        hextobyte_cache = {}
        for item in bits[1:]:
            try:
                code = item[:2]
                char = hextobyte_cache.get(code)
                if char is None:
                    char = hextobyte_cache[code] = bytes([int(code, 16)])
                appnd(char)
                appnd(item[2:])
            except:
                appnd(b'%')
                appnd(item)
        return b''.join(res)
