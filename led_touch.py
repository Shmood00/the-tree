from machine import TouchPad, Pin, PWM
from ws_mqtt import MQTTWebSocketClient
import uasyncio as asyncio
import math, time, os, gc, json
import machine
import network
from ota import OTAUpdater

FILES_TO_UPDATE = ["main.py", "led_touch.py"]

# --- CONFIG ---
def load_config():
    def _decrypt(data):
        key = machine.unique_id()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    if "config.dat" in os.listdir():
        try:
            with open("config.dat", "rb") as f:
                raw = f.read()
            decrypted = _decrypt(raw).decode()
            print("[System] Loaded encrypted config.")
            return json.loads(decrypted)
        except Exception as e:
            print("[System] Failed to decrypt config.dat:", e)

    if "config.json" in os.listdir():
        try:
            print("[System] Loading plaintext config.json")
            with open("config.json") as f:
                return json.load(f)
        except Exception as e:
            print("[System] Failed to read config.json:", e)

    print("[System] CRITICAL: No config found.")
    return {
        "url": "",
        "user": "",
        "pass": "",
        "sub_topics": [],
        "pub_topic": "touch",
        "versions": {},
        "github_url": ""
    }

CONFIG = load_config()
TOPICS = CONFIG.get("sub_topics", [])
GITHUB_URL = CONFIG.get("github_url", "")

client = None
publish_deadline = 0
mqtt_state = [0]
status = {"touch_active": False}

last_connect_time = 0

# --- HELPERS ---
def ensure_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    for _ in range(20):
        if wlan.isconnected():
            return True
        time.sleep(0.5)
    return False

async def clear_reset_flag():
    await asyncio.sleep(5)
    try:
        if ".reset_flag" in os.listdir():
            os.remove(".reset_flag")
            print("[System] Reset flag cleared.")
    except:
        pass

async def calibrate_touch(tp, samples=20):
    print("[Touch] Calibrating...")
    total = 0
    for _ in range(samples):
        total += tp.read()
        await asyncio.sleep_ms(50)
    baseline = total // samples
    threshold = int(baseline * 0.8)
    print("[Touch] Threshold:", threshold)
    return threshold

# --- MQTT CALLBACK ---
async def on_msg(topic, payload):
    global client
    t = topic.decode()
    p = payload.decode()
    print(f"[MQTT] {t} -> {p}")

    if t == "tree/cmd/update":
        print("[System] OTA reboot requested.")

        try:
            await client.disconnect()
        except:
            pass

        await asyncio.sleep(0.5)

        # 🔴 CRITICAL: fully disable WiFi before reset
        try:
            wlan = network.WLAN(network.STA_IF)
            wlan.active(False)
            await asyncio.sleep(0.5)
        except:
            pass

        machine.reset()

    mqtt_state[0] = time.ticks_add(time.ticks_ms(), 5000)

# --- LED TASK ---
async def pulse_led(led_pwm):
    phase = 0
    while True:
        await asyncio.sleep_ms(20)
        active = (
            status["touch_active"] or
            time.ticks_diff(mqtt_state[0], time.ticks_ms()) > 0
        )
        if active:
            brightness = int((math.sin(phase) * 0.5 + 0.5) * 1023)
            led_pwm.duty(brightness)
            phase += 0.1
        else:
            led_pwm.duty(0)
            phase = 0

# --- MAIN ---
async def listen():
    global client, publish_deadline, last_connect_time

    print("[System] Booting...")

    # --- OTA CHECK ---
    print("[System] Checking for updates...")
    gc.collect()

    if ensure_wifi():
        try:
            ota = OTAUpdater(GITHUB_URL, FILES_TO_UPDATE)
            if ota.check_and_update(CONFIG):
                return
        except Exception as e:
            print("[OTA] Skipped:", e)
    else:
        print("[OTA] WiFi not ready, skipping OTA.")

    # --- HARDWARE ---
    touch = TouchPad(Pin(27))
    led_pwm = PWM(Pin(33))
    led_pwm.freq(500)
    threshold = await calibrate_touch(touch)

    # --- MQTT ---
    client = MQTTWebSocketClient(
        CONFIG["url"],
        username=CONFIG["user"],
        password=CONFIG["pass"],
        ssl_params={"cert_reqs": 0},
        keepalive=30
    )
    client.set_callback(on_msg)

    asyncio.create_task(pulse_led(led_pwm))
    asyncio.create_task(clear_reset_flag())

    print("[System] Main loop running.")

    while True:
        if not client._connected:
            try:
                print("[MQTT] Connecting...")
                await client.connect()
                for t in TOPICS:
                    await client.subscribe(t)
                print("[MQTT] Connected.")

                last_connect_time = time.time()
              
            except Exception as e:
                print("[MQTT] Failed:", e)
                await asyncio.sleep(5)
                continue
        # Implement casual reconnects to ensure resilliency
        if client._connected and time.time() - last_connect_time > (6*3600):
            print("[MQTT] Proactive reconnect (socket hygiene)")
            try:
                await client.disconnect()
            except:
                pass
            client._connected = False
        
        try:
            val = touch.read()
            if val < threshold:
                status["touch_active"] = True
                if time.ticks_diff(time.ticks_ms(), publish_deadline) > 0:
                    await client.publish(CONFIG["pub_topic"], str(val))
                    publish_deadline = time.ticks_add(time.ticks_ms(), 5000)
            else:
                status["touch_active"] = False
        except Exception as e:
            print("[MQTT] Error:", e)
            client._connected = False

        await asyncio.sleep_ms(50)

if __name__ == "__main__":
    try:
        asyncio.run(example())
    except Exception as e:
        print("[Fatal]", e)
        time.sleep(3)
        machine.reset()
