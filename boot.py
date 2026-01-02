import machine
import os
import time

FLAG_FILE = ".reset_flag"
WIFI_FILE = "wifi.dat"
OTA_FLAG = ".ota_running"

led = machine.Pin(33, machine.Pin.OUT)

# --- OTA BOOT ---
if OTA_FLAG in os.listdir():
    print("[System] Post-OTA boot.")
    try:
        os.remove(OTA_FLAG)
        if FLAG_FILE in os.listdir():
            os.remove(FLAG_FILE)
    except:
        pass

    # 🔴 Allow WiFi stack to stabilize
    time.sleep(2)

# --- DOUBLE RESET ---
elif FLAG_FILE in os.listdir():
    print("[System] Double reset detected. Wiping WiFi.")

    for _ in range(15):
        led.value(0)
        time.sleep_ms(50)
        led.value(1)
        time.sleep_ms(50)

    try:
        os.remove(WIFI_FILE)
    except:
        pass

    try:
        os.remove(FLAG_FILE)
    except:
        pass

    machine.reset()

# --- NORMAL BOOT ---
else:
    if WIFI_FILE in os.listdir():
        print("[System] Setting reset flag.")
        with open(FLAG_FILE, "w") as f:
            f.write("1")
    else:
        print("[System] No WiFi config found.")

# --- WIFI CONNECT ---
from wifimanager import WifiManager
wm = WifiManager(
    ssid="Family Ornament",
    password="",
    reboot=True,
    debug=True
)
wm.connect()
