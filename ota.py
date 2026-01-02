import urequests
import os
import machine
import gc
import json
import time
import urandom

class OTAUpdater:
    def __init__(self, repo_url, filenames):
        self.repo_url = repo_url
        self.filenames = filenames

    def _xor_crypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        key = machine.unique_id()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def check_and_update(self, local_config):
        if "versions" not in local_config:
            local_config["versions"] = {}

        gc.collect()
        updated = False
        cb = urandom.getrandbits(24)

        try:
            url = f"{self.repo_url}/versions.json?cb={cb}"
            print("[OTA] Checking for updates...")

            start = time.ticks_ms()
            res = urequests.get(url)
            if time.ticks_diff(time.ticks_ms(), start) > 8000:
                raise Exception("HTTP timeout")

            remote = res.json()
            res.close()

            for fname in self.filenames:
                local = local_config["versions"].get(fname, 0)
                remote_v = remote.get(fname, 0)

                if float(remote_v) > float(local):
                    print(f"[OTA] Updating {fname}")
                    if self._download_file(fname):
                        local_config["versions"][fname] = remote_v
                        updated = True
                else:
                    print(f"[OTA] {fname} OK")

            if updated:
                self._finalize_update(local_config)
                return True

        except Exception as e:
            print("[OTA] Failed:", e)

        return False

    def _download_file(self, filename):
        gc.collect()
        try:
            url = f"{self.repo_url}/{filename}"
            res = urequests.get(url, stream=True)
            if res.status_code == 200:
                tmp = f"tmp_{filename}"
                with open(tmp, "wb") as f:
                    while True:
                        chunk = res.raw.read(128)
                        if not chunk:
                            break
                        f.write(chunk)
                res.close()
                try:
                    os.remove(filename)
                except:
                    pass
                os.rename(tmp, filename)
                return True
        except:
            pass
        return False

    def _finalize_update(self, config):
        try:
            print("[OTA] Saving config...")
            enc = self._xor_crypt(json.dumps(config))
            with open("config.dat.tmp", "wb") as f:
                f.write(enc)
            try:
                os.remove("config.dat")
            except:
                pass
            os.rename("config.dat.tmp", "config.dat")

            with open(".ota_running", "w") as f:
                f.write("1")

            print("[OTA] Rebooting...")
            time.sleep(1)
            machine.reset()

        except Exception as e:
            print("[OTA] Finalize failed:", e)
