import os, re, subprocess, tempfile, json, time, requests, shutil, base64, sqlite3
from urllib.parse import urlparse, parse_qs
from telethon import TelegramClient
from telethon.sessions import StringSession

# ---------------- تنظیمات ----------------
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
SESSION_STR = os.environ["SESSION_STRING"]

CHANNELS = ["@SOSkeyNET", "@Mrshahabx", "@vslshi"]

CONFIG_FILE = "configs.txt"
DB_FILE = "tested_configs.db"
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 1
MAX_TEST = 6000
BATCH_SIZE = 100

EXPIRY_HOURS = 12
MAX_RETEST = 40
MAX_FAILURES = 2
PURGE_INTERVAL = 2

# ---------------- کلاینت تلگرام ----------------
client = TelegramClient(StringSession(SESSION_STR), API_ID, API_HASH)

# ---------------- فیلتر بسیار سخت‌گیرانه و دقیق ----------------
def is_invalid_sni(s):
    if not s: 
        return False
    s = s.lower().strip()
    
    # مسدودسازی استفاده از آی‌پی به جای دامنه
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s): 
        return True
        
    # لیست سیاه بسیار گسترده دامنه‌های زباله و کلودفلر رایگان
    bad_domains = [
        "workers.dev", "pages.dev", "fastly.net", "ndjp.net", "ccwu.cc",
        "chickenkiller.com", "09vpn.com", "gamelistak.com", "boobie.eu.cc",
        "pink-perfect.ru", "stardevs.top", "ziqiyun.xyz", "rooster465.autos",
        "myfymain.com", "fromblancwithlove.com", "octopusss", "picassooo.info",
        "mammad.shop", "g9q.fun", "rainzone.ir", "samanehha.co", "s3-cloud.xyz",
        "ignorelist.com", "solid-dev1.online", "twilightparadox.com", "bexum.fun",
        "cgiproxy", "connectv.net", "cnae.top", "9889888.xyz", "cfvip.lol",
        "sajadi.lol", "ir" # دامنه های .ir برای خروج از کشور منطقی نیستند و بلاک میشوند
    ]
    if any(bd in s for bd in bad_domains): 
        return True
        
    return False

def is_burned_reality_sni(s):
    s = s.lower().strip()
    burned = [
        "yahoo", "microsoft", "cloudflare", "sony", "apple", "icloud", 
        "amazon", "max.ru", "vk-portal", "deepl", "tradingview", "yandex",
        "mozilla", "vk.com", "speedtest", "zoom.us", "google", "ya.ru",
        "alibaba", "kinopoisk", "vk.ru", "sberbank", "ebay", "asus.com"
    ]
    if any(b in s for b in burned): 
        return True
    return False

def is_iran_friendly_config(link):
    """
    قوانین جدید بر اساس تحلیل رفتاری DPI:
    1. تروجان مسدود است.
    2. Vless بدون TLS/Reality مسدود است.
    3. داشتن fp معتبر (chrome/firefox/edge) برای Vless الزامی است.
    """
    try:
        CF_TLS_PORTS = {443, 2053, 2083, 2087, 8443, 2096}
        CF_HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
        
        # تروجان دراپ می‌شود
        if link.startswith("trojan://"):
            return False

        if link.startswith("vmess://"):
            b64 = link[8:]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            decoded = json.loads(base64.b64decode(b64).decode('utf-8'))
            port = int(decoded.get("port", 443))
            net = decoded.get("net", "tcp")
            tls = decoded.get("tls", "")
            sni = decoded.get("sni", "")
            host = decoded.get("host", "")
            
            if net == "tcp" and tls != "tls": return False
            if tls != "tls" and port not in CF_HTTP_PORTS: return False
            if tls == "tls" and port not in CF_TLS_PORTS: return False
            if is_invalid_sni(sni) or is_invalid_sni(host): return False
            return True

        elif link.startswith("ss://"):
            parsed = urlparse(link)
            port = parsed.port
            if not port: return False
            # SS روی پورت 443 مسدود است، اما روی 8080 اوکی است
            if port == 443: return False
            if port not in CF_HTTP_PORTS and port not in [8443, 2053]: return False
            return True

        elif link.startswith("vless://"):
            parsed = urlparse(link)
            port = parsed.port if parsed.port else 443
            params = parse_qs(parsed.query)
            
            security = params.get("security", [""])[0]
            net_type = params.get("type", ["tcp"])[0]
            fp = params.get("fp", [""])[0]
            pbk = params.get("pbk", [""])[0]
            sni = params.get("sni", [""])[0]
            host = params.get("host", [""])[0]
            
            actual_sni = sni or host or parsed.hostname
            if is_invalid_sni(actual_sni): return False
            
            # VLESS بدون امنیت (none) به طور قطع مسدود می‌شود
            if security not in ["tls", "reality"]: 
                return False

            # دارا بودن اثر انگشت معتبر الزامی است
            if fp not in ["chrome", "firefox", "edge", "safari"]: 
                return False
            
            if security == "reality":
                if not pbk: return False
                if is_burned_reality_sni(actual_sni): return False
                
            elif security == "tls":
                if port not in CF_TLS_PORTS: return False
                
            return True
            
    except Exception:
        return False
    return False

# ---------------- پاکسازی دیتابیس ----------------
def clean_database_with_heuristics():
    print("🔍 در حال اسکن دیتابیس برای حذف کانفیگ‌های فاقد استاندارد جدید...")
    if not os.path.exists(DB_FILE):
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tested_configs'")
        if not c.fetchone():
            conn.close()
            return

        c.execute("SELECT config_hash FROM tested_configs")
        rows = c.fetchall()
        removed_count = 0
        
        for row in rows:
            config_hash = row[0]
            if not is_iran_friendly_config(config_hash):
                c.execute("DELETE FROM tested_configs WHERE config_hash=?", (config_hash,))
                removed_count += 1
                
        conn.commit()
        if removed_count > 0:
            print(f"🧹 پاکسازی دیتابیس: {removed_count} کانفیگ قدیمی ناسازگار از دیتابیس حذف شدند.\n")
        else:
            print("✅ دیتابیس تمیز است.\n")
    except Exception as e:
        print(f"⚠️ خطا در پاکسازی دیتابیس: {e}")
    finally:
        conn.close()

# ---------------- توابع پایگاه داده و وضعیت ----------------
def init_fetch_state():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS fetch_state
                 (channel TEXT PRIMARY KEY, last_msg_id INTEGER)''')
    conn.commit()
    conn.close()

def get_last_msg_id(channel):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT last_msg_id FROM fetch_state WHERE channel=?", (channel,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0

def set_last_msg_id(channel, msg_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO fetch_state VALUES (?, ?)", (channel, msg_id))
    conn.commit()
    conn.close()

def extract_configs():
    configs = set()
    with client:
        for channel in CHANNELS:
            last_id = get_last_msg_id(channel)
            new_messages = []
            max_id = last_id
            try:
                messages = client.iter_messages(
                    channel,
                    limit=200,
                    min_id=last_id + 1,
                    reverse=False
                )
                for msg in messages:
                    new_messages.append(msg)
                    if msg.id > max_id:
                        max_id = msg.id
            except Exception as e:
                print(f"⚠️ خطا در دریافت پیام‌های کانال {channel}: {e}")
                continue
            if new_messages:
                set_last_msg_id(channel, max_id)
                print(f"📨 {channel}: {len(new_messages)} پیام جدید (آخرین ID: {max_id})")
            else:
                print(f"📨 {channel}: پیام جدیدی یافت نشد.")
            for msg in new_messages:
                if msg.text:
                    found = re.findall(r'(?:vless|vmess|trojan|ss)://\S+', msg.text)
                    for link in found:
                        if is_iran_friendly_config(link):
                            configs.add(link)
    return list(configs)

def init_run_counter():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS run_counter
                 (id INTEGER PRIMARY KEY, counter INTEGER)''')
    c.execute("INSERT OR IGNORE INTO run_counter (id, counter) VALUES (1, 0)")
    conn.commit()
    conn.close()

def get_run_counter():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT counter FROM run_counter WHERE id=1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0

def set_run_counter(value):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE run_counter SET counter=? WHERE id=1", (value,))
    conn.commit()
    conn.close()

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS tested_configs
                 (config_hash TEXT PRIMARY KEY, real_delay REAL, last_test_time REAL)''')
    try:
        c.execute("ALTER TABLE tested_configs ADD COLUMN fail_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

def is_config_tested(config_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT real_delay FROM tested_configs WHERE config_hash=?", (config_hash,))
    result = c.fetchone()
    conn.close()
    return result is not None

def save_tested_config(config_hash, real_delay, fail_count=0):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO tested_configs VALUES (?, ?, ?, ?)",
              (config_hash, real_delay, time.time(), fail_count))
    conn.commit()
    conn.close()

def delete_config(config_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM tested_configs WHERE config_hash=?", (config_hash,))
    conn.commit()
    conn.close()

def increment_fail_count(config_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE tested_configs SET fail_count = fail_count + 1, last_test_time = ? WHERE config_hash=?",
              (time.time(), config_hash))
    conn.commit()
    conn.close()

def get_fail_count(config_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT fail_count FROM tested_configs WHERE config_hash=?", (config_hash,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0

def get_cached_configs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT config_hash, real_delay FROM tested_configs ORDER BY real_delay ASC")
    results = c.fetchall()
    conn.close()
    return results

def get_expired_configs(limit):
    cutoff = time.time() - EXPIRY_HOURS * 3600
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT config_hash, last_test_time, fail_count FROM tested_configs WHERE last_test_time < ? ORDER BY last_test_time ASC LIMIT ?",
              (cutoff, limit))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------------- ابزار git ----------------
def setup_git():
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=True)
    subprocess.run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=True)

def commit_and_push(valid_configs, new_count, total_valid):
    content = "\n".join(valid_configs)
    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(encoded)

    subprocess.run(["git", "add", CONFIG_FILE, DB_FILE], check=True)

    result = subprocess.run(["git", "diff", "--cached", "--quiet"], capture_output=True)
    if result.returncode == 0:
        print("   ↳ بدون تغییر جدید، commit انجام نشد.")
        return

    commit_msg = f"🔄 Update: +{new_count} new configs (total valid: {total_valid})"
    subprocess.run(["git", "commit", "-m", commit_msg], check=True)
    subprocess.run(["git", "pull", "--rebase", "origin", "main"], check=True)
    subprocess.run(["git", "push", "origin", "main"], check=True)
    print(f"   ↳ تغییرات با موفقیت push شد ({total_valid} کانفیگ معتبر).")

# ---------------- دانلود Xray-core ----------------
def download_xray():
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    resp = requests.get(url, stream=True, timeout=30)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        for chunk in resp.iter_content(chunk_size=8192):
            tmp.write(chunk)
        zip_path = tmp.name
    xray_dir = tempfile.mkdtemp()
    shutil.unpack_archive(zip_path, xray_dir)
    xray_bin = os.path.join(xray_dir, "xray")
    os.chmod(xray_bin, 0o755)
    return xray_bin

# ---------------- تبدیل لینک به Outbound Xray ----------------
def parse_link_to_outbound(link):
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            padded = b64 + '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else b64
            decoded = json.loads(base64.b64decode(padded).decode('utf-8'))
            out = {
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": decoded["add"],
                    "port": int(decoded["port"]),
                    "users": [{"id": decoded["id"], "security": decoded.get("scy", "auto")}]
                }]},
                "streamSettings": {"network": decoded.get("net", "tcp")}
            }
            if decoded.get("net") == "ws":
                out["streamSettings"]["wsSettings"] = {
                    "path": decoded.get("path", "/"),
                    "headers": {"Host": decoded.get("host", decoded["add"])} if decoded.get("host") else {}
                }
            if decoded.get("tls") == "tls":
                out["streamSettings"]["security"] = "tls"
                out["streamSettings"]["tlsSettings"] = {"serverName": decoded.get("sni", decoded["add"])}
            return out

        elif link.startswith("ss://"):
            parsed = urlparse(link)
            userinfo = parsed.username
            if userinfo:
                try:
                    padded = userinfo + '=' * (4 - len(userinfo) % 4) if len(userinfo) % 4 != 0 else userinfo
                    decoded = base64.b64decode(padded).decode('utf-8')
                    if ':' in decoded:
                        method, password = decoded.split(':', 1)
                    else:
                        method = "aes-256-gcm"
                        password = decoded
                except:
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                    else:
                        method, password = "aes-256-gcm", userinfo
            else:
                return None
            address = parsed.hostname
            port = parsed.port
            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": address,
                        "port": int(port),
                        "method": method,
                        "password": password
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none"
                }
            }
            return outbound

        elif link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urlparse(link)
            if link.startswith("vless://"):
                uuid = parsed.username
                protocol = "vless"
                settings = {"vnext": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [{"id": uuid, "encryption": "none", "flow": ""}]
                }]}
            else:
                password = parsed.username
                protocol = "trojan"
                settings = {"servers": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "password": password
                }]}

            params = parse_qs(parsed.query)
            def get_param(key, default=""):
                return params.get(key, [default])[0]

            network = get_param("type", "tcp")
            security = get_param("security", "none")
            sni = get_param("sni", parsed.hostname)
            host = get_param("host", "")
            path = get_param("path", "/")
            header_type = get_param("headerType", "none")
            alpn = get_param("alpn", "")
            fp = get_param("fp", "")
            flow = get_param("flow", "")
            if protocol == "vless" and flow:
                settings["vnext"][0]["users"][0]["flow"] = flow

            outbound = {
                "protocol": protocol,
                "settings": settings,
                "streamSettings": {
                    "network": network,
                    "security": security
                }
            }

            if network == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": path,
                    "headers": {"Host": host} if host else {}
                }
            elif network == "tcp":
                if header_type == "http":
                    outbound["streamSettings"]["tcpSettings"] = {
                        "header": {
                            "type": "http",
                            "request": {
                                "headers": {"Host": host} if host else {},
                                "path": path if path != "/" else "/"
                            }
                        }
                    }
                elif header_type and header_type != "none":
                    outbound["streamSettings"]["tcpSettings"] = {"header": {"type": header_type}}
            elif network == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": path.lstrip("/"),
                    "multiMode": False
                }
            elif network == "xhttp":
                outbound["streamSettings"]["xhttpSettings"] = {
                    "mode": get_param("mode", "auto"),
                    "path": path,
                    "host": host
                }
            elif network == "httpupgrade":
                outbound["streamSettings"]["httpupgradeSettings"] = {
                    "path": path,
                    "host": host
                }

            if security == "tls":
                tls_settings = {"serverName": sni, "allowInsecure": get_param("allowInsecure", "0") == "1"}
                if alpn:
                    tls_settings["alpn"] = alpn.split(",")
                if fp:
                    tls_settings["fingerprint"] = fp
                outbound["streamSettings"]["tlsSettings"] = tls_settings
            elif security == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": sni,
                    "fingerprint": fp if fp else "chrome",
                    "publicKey": get_param("pbk", ""),
                    "shortId": get_param("sid", ""),
                    "spiderX": get_param("spx", "")
                }

            return outbound

    except Exception:
        return None

def test_single_config(xray_bin, link, timeout=TEST_TIMEOUT):
    outbound = parse_link_to_outbound(link)
    if not outbound:
        return False, 999999

    inbound = {
        "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
        "settings": {"udp": False, "auth": "noauth"}
    }
    config = {"inbounds": [inbound], "outbounds": [outbound]}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    xray_proc = None
    try:
        xray_proc = subprocess.Popen(
            [xray_bin, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2.5)

        res = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
             "--socks5-hostname", "127.0.0.1:10808", TEST_URL,
             "--connect-timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 5
        )

        if res.returncode == 0 and res.stdout.strip():
            latency = float(res.stdout.strip()) * 1000
            if latency < timeout * 1000:
                return True, latency
        return False, 999999

    except Exception:
        return False, 999999
    finally:
        if xray_proc:
            xray_proc.terminate()
            try:
                xray_proc.wait(timeout=3)
            except:
                xray_proc.kill()
        try:
            os.unlink(config_path)
        except:
            pass

def test_all_with_incremental_save(configs):
    print("📥 دانلود Xray-core...")
    xray_bin = download_xray()
    print("✅ Xray-core آماده شد.\n")

    results = {}
    new_in_batch = 0
    total_processed = 0
    total = len(configs)

    cached = get_cached_configs()
    for config_hash, delay in cached:
        results[config_hash] = delay
    print(f"📊 {len(cached)} کانفیگ معتبر از پایگاه داده بازیابی شد.\n")

    for i, link in enumerate(configs, 1):
        total_processed += 1
        short = link[:70] + ("..." if len(link) > 70 else "")

        if is_config_tested(link):
            print(f"[{i}/{total}] ⏭️ {short} → قبلاً تست شده")
            continue

        ok, delay = test_single_config(xray_bin, link)

        if ok:
            results[link] = delay
            save_tested_config(link, delay, fail_count=0)
            new_in_batch += 1
            print(f"[{i}/{total}] ✅ {short} → Real Delay: {delay:.0f}ms")
        else:
            print(f"[{i}/{total}] ❌ {short} → ناموفق")

        if total_processed % BATCH_SIZE == 0 or i == total:
            if new_in_batch > 0:
                sorted_links = [link for link, _ in sorted(results.items(), key=lambda x: x[1])]
                total_valid = len(sorted_links)
                print(f"\n📦 پایان دسته {total_processed}/{total} | +{new_in_batch} جدید معتبر (کل: {total_valid})")
                commit_and_push(sorted_links, new_in_batch, total_valid)
                new_in_batch = 0
            else:
                print(f"\n📦 پایان دسته {total_processed}/{total} | بدون جدید معتبر")

    print("\n🔁 شروع بازبینی کانفیگ‌های قدیمی...")
    expired = get_expired_configs(MAX_RETEST)
    if not expired:
        print("✅ هیچ کانفیگ منقضی شده‌ای یافت نشد.")
    else:
        recheck_changes = False
        for config_hash, last_time, fail_count in expired:
            short = config_hash[:70] + ("..." if len(config_hash) > 70 else "")
            ok, delay = test_single_config(xray_bin, config_hash)

            if ok:
                save_tested_config(config_hash, delay, fail_count=0)
                results[config_hash] = delay
                print(f"🔁 ✅ {short} → دوباره سالم شد")
                recheck_changes = True
            else:
                increment_fail_count(config_hash)
                new_fail_count = get_fail_count(config_hash)
                print(f"🔁 ❌ {short} → (شکست {new_fail_count} از {MAX_FAILURES})")
                if new_fail_count >= MAX_FAILURES:
                    delete_config(config_hash)
                    if config_hash in results:
                        del results[config_hash]
                    print(f"   🗑️ حذف شد")
                    recheck_changes = True

        if recheck_changes:
            sorted_links = [link for link, _ in sorted(results.items(), key=lambda x: x[1])]
            total_valid = len(sorted_links)
            commit_and_push(sorted_links, 0, total_valid)

    shutil.rmtree(os.path.dirname(xray_bin), ignore_errors=True)
    print(f"\n🔚 تست تمام شد. مجموع معتبرها: {len(results)}")
    return [link for link, _ in sorted(results.items(), key=lambda x: x[1])]

def perform_purge():
    print("🧹 شروع پالایش کامل کانفیگ‌های موجود...")
    if not os.path.exists(CONFIG_FILE):
        return

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        encoded = f.read().strip()
    if not encoded:
        set_run_counter(0)
        return

    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
        links = [line.strip() for line in decoded.split("\n") if line.strip()]
    except Exception:
        return

    unique_links = list(set(links))
    xray_bin = download_xray()
    results = {}
    removed = 0

    for link in unique_links:
        ok, delay = test_single_config(xray_bin, link)
        if ok:
            results[link] = delay
            save_tested_config(link, delay, fail_count=0)
        else:
            delete_config(link)
            removed += 1

    sorted_links = [link for link, _ in sorted(results.items(), key=lambda x: x[1])]
    total_valid = len(sorted_links)
    print(f"\n🧹 پالایش پایان یافت. {total_valid} معتبر باقی ماندند (حذف: {removed})")
    commit_and_push(sorted_links, 0, total_valid)
    set_run_counter(0)
    shutil.rmtree(os.path.dirname(xray_bin), ignore_errors=True)

if __name__ == "__main__":
    init_db()
    clean_database_with_heuristics()
    init_fetch_state()
    init_run_counter()
    setup_git()

    counter = get_run_counter()
    if counter >= PURGE_INTERVAL:
        print(f"🔄 شمارنده اجرا: {counter} (آستانه: {PURGE_INTERVAL}) → اجرای پالایش")
        perform_purge()
        exit(0)

    print(f"📊 شمارنده اجرا: {counter} / {PURGE_INTERVAL} → اجرای عادی")
    print("📡 دریافت کانفیگ‌ها از تلگرام...")
    raw = extract_configs()
    print(f"📋 {len(raw)} کانفیگ یکتا پس از فیلترینگ بسیار سخت‌گیرانه، برای تست آماده شد.\n")

    if not raw:
        print("⚠️ هیچ کانفیگ سالمی پیدا نشد!")
        set_run_counter(counter + 1)
        exit(1)

    if len(raw) > MAX_TEST:
        raw = raw[:MAX_TEST]

    valid = test_all_with_incremental_save(raw)

    content = "\n".join(valid)
    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(encoded)

    set_run_counter(counter + 1)
    print(f"🔢 شمارنده اجرا به‌روز شد: {counter + 1} / {PURGE_INTERVAL}")
