# yoinked
import base64
import hashlib
import json
import os
import random
from pathlib import Path
from urllib.parse import parse_qsl
import concurrent.futures
import requests
import requests.cookies
import urllib3
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from win32 import win32crypt
from loguru import logger

urllib3.disable_warnings()

class DgpSessionUtils:
    @staticmethod
    def gen_rand_hex():
        return hashlib.sha256(str(random.random()).encode()).hexdigest()

    @staticmethod
    def gen_rand_address():
        hex_str = DgpSessionUtils.gen_rand_hex()
        address = ""
        for x in range(12):
            address += hex_str[x]
            if x % 2 == 1:
                address += ":"
        return address[:-1]

class DgpSession:
    DGP5_PATH = Path(os.environ["PROGRAMFILES"]).joinpath("DMMGamePlayer")
    DGP5_DATA_PATH = Path(os.environ["APPDATA"]).joinpath("dmmgameplayer5")

    HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    }
    DGP5_HEADERS = {
        "Connection": "keep-alive",
        "User-Agent": "DMMGamePlayer5-Win/5.3.25 Electron/34.3.0",
        "Client-App": "DMMGamePlayer5",
        "Client-Version": "5.3.25",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "ja",
        "Priority": "u=1, i",
    }
    DGP5_DEVICE_PARAMS = {
        "mac_address": DgpSessionUtils.gen_rand_address(),
        "hdd_serial": DgpSessionUtils.gen_rand_hex(),
        "motherboard": DgpSessionUtils.gen_rand_hex(),
        "user_os": "win",
    }
    DATA_DESCR = "UmaLauncher"

    API_DGP = "https://apidgp-gameplayer.games.dmm.com{0}"
    LAUNCH_CL = API_DGP.format("/v5/r2/launch/cl")

    actauth = None
    session = None

    def __init__(self):
        self.actauth = {}
        self.session = requests.Session()
        self.session.cookies = requests.cookies.RequestsCookieJar()
        self.session.cookies.set("age_check_done", "0", domain=".dmm.com", path="/")

    def write_safe(self, data):
        file = self.DGP5_DATA_PATH.joinpath("authAccessTokenData.enc")
        with open(file, "wb") as f:
            f.write(data)

    def read_safe(self):
        file = self.DGP5_DATA_PATH.joinpath("authAccessTokenData.enc")
        if file.exists():
            with open(file, "rb") as f:
                return f.read()
        return None

    def write(self):
        aes_key = self.get_aes_key()
        v10 = "v10".encode()
        nonce = get_random_bytes(12)
        value = json.dumps(self.actauth).encode()
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
        data, mac = cipher.encrypt_and_digest(value)
        enc = self.join_encrypted_data(v10, nonce, data, mac)
        self.write_safe(enc)

    def read(self):
        aes_key = self.get_aes_key()
        enc = self.read_safe()
        if enc:
            v10, nonce, data, mac = self.split_encrypted_data(enc)
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
            value = cipher.decrypt_and_verify(data, mac)
            self.actauth = json.loads(value.decode())
        else:
            self.actauth = {}

    def get_access_token(self):
        return self.actauth.get("accessToken")

    def get_headers(self):
        return self.DGP5_HEADERS | {"actauth": self.get_access_token()}

    def get_dgp(self, url, params=None, **kwargs):
        logger.debug(f"GET {url} params={params}")
        res = self.session.get(url, headers=self.get_headers(), params=params, **kwargs)
        if res.headers.get("Content-Type") == "application/json":
            logger.debug(f"Response: {res.text}")
        return res

    def get(self, url, params=None, **kwargs):
        logger.debug(f"GET {url}")
        res = self.session.get(url, headers=self.HEADERS, params=params, **kwargs)
        return res

    def post_dgp(self, url, json_data=None, **kwargs):
        logger.debug(f"POST {url} json={json_data}")
        res = self.session.post(url, headers=self.get_headers(), json=json_data, **kwargs)
        if res.headers.get("Content-Type") == "application/json":
            logger.debug(f"Response: {res.text}")
        return res

    def post_device_dgp(self, url, json_data=None, **kwargs):
        json_data = (json_data or {}) | self.DGP5_DEVICE_PARAMS
        return self.post_dgp(url, json_data=json_data, **kwargs)

    def launch(self, product_id, game_type):
        json_data = {
            "product_id": product_id,
            "game_type": game_type,
            "game_os": "win",
            "launch_type": "LIB",
        }
        return self.post_device_dgp(self.LAUNCH_CL, json_data=json_data, verify=False)

    def get_config(self):
        config_file = self.DGP5_DATA_PATH.joinpath("dmmgame.cnf")
        with open(config_file, "r", encoding="utf-8") as f:
            config = f.read()
        res = json.loads(config)
        logger.debug(f"Read dmmgame.cnf: {res}")
        return res

    def set_config(self, config):
        config_file = self.DGP5_DATA_PATH.joinpath("dmmgame.cnf")
        with open(config_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(config, indent=4))

    def download(self, sign, filelist_url, output):
        sign_dict = dict(parse_qsl(sign.replace(";", "&")))
        signed = {
            "Policy": sign_dict["CloudFront-Policy"],
            "Signature": sign_dict["CloudFront-Signature"],
            "Key-Pair-Id": sign_dict["CloudFront-Key-Pair-Id"],
        }
        url = self.API_DGP.format(filelist_url)
        data = self.get_dgp(url).json()

        def download_save(file):
            path = output.joinpath(file["local_path"][1:])
            content = self.get(data["data"]["domain"] + "/" + file["path"], params=signed).content
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                f.write(content)
            return file["size"], file

        def check_sum(file):
            path = output.joinpath(file["local_path"][1:])
            if not file["check_hash_flg"]:
                return True, file
            if file["force_delete_flg"]:
                if path.exists():
                    path.unlink()
                return True, file
            if not path.exists():
                return False, file
            try:
                with open(path, "rb") as f:
                    content = f.read()
                return file["hash"] == hashlib.md5(content).hexdigest(), file
            except Exception:
                return False, file

        check_count = 0
        check_failed_list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            tasks = [pool.submit(lambda x: check_sum(x), x) for x in data["data"]["file_list"]]
            for task in concurrent.futures.as_completed(tasks):
                res, file = task.result()
                check_count += 1
                if not res:
                    check_failed_list.append(file)
                yield check_count / len(data["data"]["file_list"]), file

        yield 0, None

        check_failed_list = sorted(check_failed_list, key=lambda x: x["size"], reverse=True)
        download_max_size = sum([x["size"] for x in check_failed_list])
        download_size = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            tasks = [pool.submit(lambda x: download_save(x), x) for x in check_failed_list]
            for task in concurrent.futures.as_completed(tasks):
                size, file = task.result()
                download_size += size
                yield download_size / download_max_size, file

    def get_aes_key(self):
        with open(self.DGP5_DATA_PATH.joinpath("Local State"), "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"].encode())[5:]
        key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return key

    def split_encrypted_data(self, encrypted_data):
        return (
            encrypted_data[0:3],
            encrypted_data[3:15],
            encrypted_data[15:-16],
            encrypted_data[-16:],
        )

    def join_encrypted_data(self, v10, nonce, data, mac):
        return v10 + nonce + data + mac

    @staticmethod
    def read_dgp():
        session = DgpSession()
        session.read()
        return session

def get_launch_info(product_id="umamusume", game_type="GCL", update_callback=None):
    try:
        session = DgpSession.read_dgp()
        
        if not session.get_access_token():
            logger.error("No access token found in DMM session")
            return None
        
        dgp_config = session.get_config()
        game = None
        for content in dgp_config.get("contents", []):
            if content.get("productId") == product_id:
                game = content
                break
        
        if not game:
            logger.error(f"Game {product_id} not found in DMM config")
            return None
        
        response = session.launch(product_id, game_type)
        response_data = response.json()
        
        if response_data.get("result_code") != 100:
            logger.error(f"Launch failed: {response_data.get('error')}")
            return None
        
        game_file = Path(game["detail"]["path"])
        exec_file_name = response_data["data"]["exec_file_name"]
        execute_args = response_data["data"]["execute_args"]
        
        drm_auth_token = response_data["data"].get("drm_auth_token")
        if drm_auth_token:
            filename = base64.b64encode(product_id.encode("utf-8")).decode("utf-8")
            drm_path = Path(os.environ["LOCALAPPDATA"]).joinpath("dmmgameplayer5", "Partitions", filename)
            drm_path.parent.mkdir(parents=True, exist_ok=True)
            with open(drm_path.absolute(), "w+") as f:
                f.write(drm_auth_token)
        
        if response_data["data"]["latest_version"] != game["detail"]["version"]:
            logger.info(f"Game update available: {game['detail']['version']} -> {response_data['data']['latest_version']}")
            
            if update_callback:
                update_callback("downloading", 0)
            
            logger.info("Downloading game update...")
            total_files = 0
            downloaded_files = 0
            
            for progress, file in session.download(
                response_data["data"]["sign"],
                response_data["data"]["file_list_url"],
                game_file
            ):
                if file is None:
                    total_files = int(progress * 100)
                    logger.info(f"Checking files: {total_files} files to verify")
                    if update_callback:
                        update_callback("checking", progress)
                else:
                    downloaded_files += 1
                    if update_callback:
                        update_callback("downloading", progress, file.get("local_path", ""))
            
            game["detail"]["version"] = response_data["data"]["latest_version"]
            session.set_config(dgp_config)
            logger.info("Game updated successfully")
            
            if update_callback:
                update_callback("complete")
        
        return {
            "game_path": str(game_file),
            "exec_file": exec_file_name,
            "args": execute_args.split(" ") if execute_args else []
        }
    except Exception as e:
        logger.error(f"Failed to get launch info: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None
