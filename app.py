import time
import sys
import os
import re
import ipaddress
import geoip2.database
from datetime import datetime
from clickhouse_driver import Client
from hashlib import sha256
import requests
import urllib3
import roul
import roul.ip
import roul.asn
import roul.thread

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- MikroTik REST API Connection Settings ---
ROUTER_IP = os.getenv('MIKROTIK_ROUTER_IP', '192.168.90.1')
API_USER = os.getenv('MIKROTIK_API_USER', 'api_user')
API_PASSWORD = os.getenv('MIKROTIK_API_PASSWORD', 'your_password')
API_BASE_URL = f"https://{ROUTER_IP}/rest"
VERIFY_SSL = bool(os.getenv('MIKROTIK_VERIFY_SSL', 'False').lower() in ('true', '1', 't'))
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '5'))

# --- ClickHouse Database Settings ---
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', 'localhost')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', '9000'))
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'default')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', '')
CLICKHOUSE_DB = os.getenv('CLICKHOUSE_DB', 'mikro_traffic')
CLICKHOUSE_TABLE = os.getenv('CLICKHOUSE_TABLE', 'mikrotik_connections')

# --- GeoIP2 Database Settings ---
GEOIP_DB_DIR = os.getenv('GEOIP_DB_DIR', '.')
COUNTRY_DB_PATH = os.path.join(GEOIP_DB_DIR, 'GeoLite2-Country.mmdb')
CITY_DB_PATH = os.path.join(GEOIP_DB_DIR, 'GeoLite2-City.mmdb')
roul.asn.UA = os.getenv('UA', 'MikrotikTrafficScraper - yourmail@orgdomain.net')

country_reader: geoip2.database.Reader
city_reader: geoip2.database.Reader

def load_geoip_db():
    global country_reader, city_reader
    try:
        country_reader = geoip2.database.Reader(COUNTRY_DB_PATH)
    except FileNotFoundError:
        print(f"Error: Country database file not found at '{COUNTRY_DB_PATH}'.", file=sys.stderr)
        sys.exit(1)
    try:
        city_reader = geoip2.database.Reader(CITY_DB_PATH)
    except FileNotFoundError:
        print(f"Error: City database file not found at '{CITY_DB_PATH}'.", file=sys.stderr)
        sys.exit(1)

def split_ip_port(address: str, conn: dict, prefix: str) -> tuple[str, int]:
    # Check if port is already in the address string (e.g., "1.1.1.1:80")
    parts = address.split(':')
    if len(parts) == 2:
        return parts[0], int(parts[1])
    
    # If not, try to get it from the separate port field (e.g., "src-port")
    port = conn.get(f'{prefix}-port')
    if port:
        try:
            return address, int(port)
        except ValueError:
            pass
            
    return address, 0

def parse_timeout(timeout_str: str) -> int:
    # Handle HH:MM:SS format
    if ':' in timeout_str:
        parts = timeout_str.split(':')
        if len(parts) == 3: # HH:MM:SS
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        if len(parts) == 2: # MM:SS
            return int(parts[0]) * 60 + int(parts[1])
            
    # Handle "1d2h3m4s" or "10s" format
    total_seconds = 0
    matches = re.findall(r'(\d+)([dhms])', timeout_str)
    if matches:
        multipliers = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
        for val, unit in matches:
            total_seconds += int(val) * multipliers.get(unit, 0)
        return total_seconds
        
    # Fallback to simple digits (assume seconds)
    digits = re.findall(r'(\d+)', timeout_str)
    if digits:
        return int(digits[0])
        
    return 0

def is_ip_private(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def get_geo_info_from_ip(ipaddr: str):
    if not roul.ip.is_valid(ipaddr):
        raise ValueError(f"Invalid IP address: {ipaddr}")
    
    try:
        this_city_reader = city_reader.city(ipaddr)
    except Exception:
        this_city_reader = None
    
    try:
        if this_city_reader:
            iso_code = this_city_reader.registered_country.iso_code
            full_name = this_city_reader.registered_country.name
        else:
            iso_code = ""
            full_name = ""
    except Exception as e:
        print(f"Error fetching country info for {ipaddr}: {e}", file=sys.stderr)
        iso_code = ""
        full_name = ""

    try:
        asn = roul.asn.search_asn_as_ip(ipaddr)
        asn_name = roul.asn.search_asn_name(asn)
    except Exception:
        asn = 0
        asn_name = ""

    try:
        if this_city_reader:
            latitude = this_city_reader.location.latitude
            longitude = this_city_reader.location.longitude
        else:
            latitude = 0.0
            longitude = 0.0
    except Exception as e:
        print(f"Error fetching location info for {ipaddr}: {e}", file=sys.stderr)
        latitude = 0.0
        longitude = 0.0

    try:
        if this_city_reader:
            city_name = this_city_reader.city.name
        else:
            city_name = ""
    except Exception as e:
        print(f"Error fetching city info for {ipaddr}: {e}", file=sys.stderr)
        city_name = ""
    
    iso_code = "" if not iso_code else iso_code
    full_name = "" if not full_name else full_name
    asn = 0 if not asn else asn
    asn_name = "" if not asn_name else asn_name
    latitude = 0.0 if not latitude else latitude
    longitude = 0.0 if not longitude else longitude
    city_name = "" if not city_name else city_name

    data: dict[str, str | int | float] = {
        "asn": asn,
        "asn_name": asn_name,
        "country": iso_code,
        "country_name": full_name,
        "city": city_name,
        "latitude": int(latitude * 1000),
        "longitude": int(longitude * 1000)
    }

    return data

def collect_and_push_metrics():
    try:
        session = requests.Session()
        session.auth = (API_USER, API_PASSWORD)
        connections_url = f"{API_BASE_URL}/ip/firewall/connection"
        connection_response = session.get(connections_url, verify=VERIFY_SSL, timeout=30)
        connection_response.raise_for_status()
        connections = connection_response.json()
        print(f"[{time.ctime()}] Successfully fetched {len(connections)} connections.")

        records_to_insert = []
        current_time = datetime.now()

        for conn in connections:
            _id = conn.get('.id', '0')
            src_address_full = conn.get('src-address', 'unknown')
            dst_address_full = conn.get('dst-address', 'unknown')
            reply_src_address_full = conn.get('reply-src-address', 'unknown')
            reply_dst_address_full = conn.get('reply-dst-address', 'unknown')
            protocol = conn.get('protocol', 'unknown')
            orig_bytes = int(conn.get('orig-bytes', '0'))
            orig_packets = int(conn.get('orig-packets', '0'))
            orig_rate = int(conn.get('orig-rate', '0'))
            orig_fasttrack_bytes = int(conn.get('orig-fasttrack-bytes', '0'))
            orig_fasttrack_packets = int(conn.get('orig-fasttrack-packets', '0'))
            repl_bytes = int(conn.get('repl-bytes', '0'))
            repl_packets = int(conn.get('repl-packets', '0'))
            repl_rate = int(conn.get('repl-rate', '0'))
            repl_fasttrack_bytes = int(conn.get('repl-fasttrack-bytes', '0'))
            repl_fasttrack_packets = int(conn.get('repl-fasttrack-packets', '0'))
            tcp_state = conn.get('tcp-state', 'none')
            timeout_str = conn.get('timeout', '0')
            timeout = parse_timeout(timeout_str)
            
            connection_id = sha256(f"{_id}{src_address_full}{dst_address_full}{protocol}".encode()).digest()
            
            if protocol == "tcp":
                tcp_state = conn.get('tcp-state', 'unknown')

            src_ip, src_port = split_ip_port(src_address_full, conn, 'src')
            dst_ip, dst_port = split_ip_port(dst_address_full, conn, 'dst')
            reply_src_ip, reply_src_port = split_ip_port(reply_src_address_full, conn, 'reply-src')
            reply_dst_ip, reply_dst_port = split_ip_port(reply_dst_address_full, conn, 'reply-dst')
            
            # Determine if connection is strictly private (both ends are private)
            is_private = 1 if (is_ip_private(src_ip) and is_ip_private(dst_ip)) else 0
            
            src_geo_info = get_geo_info_from_ip(src_ip)
            dst_geo_info = get_geo_info_from_ip(dst_ip)
            reply_src_geo_info = get_geo_info_from_ip(reply_src_ip)
            reply_dst_geo_info = get_geo_info_from_ip(reply_dst_ip)
            
            try:
                records_to_insert.append((
                    current_time,
                    connection_id,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    protocol,
                    orig_bytes,
                    orig_packets,
                    orig_rate,
                    orig_fasttrack_bytes,
                    orig_fasttrack_packets,
                    tcp_state,
                    timeout,
                    src_geo_info['asn'],
                    src_geo_info['asn_name'],
                    src_geo_info['country'],
                    src_geo_info['country_name'],
                    src_geo_info['city'],
                    src_geo_info['latitude'],
                    src_geo_info['longitude'],
                    dst_geo_info['asn'],
                    dst_geo_info['asn_name'],
                    dst_geo_info['country'],
                    dst_geo_info['country_name'],
                    dst_geo_info['city'],
                    dst_geo_info['latitude'],
                    dst_geo_info['longitude'],
                    is_private
                ))
                records_to_insert.append((
                    current_time,
                    connection_id,
                    reply_src_ip,
                    reply_src_port,
                    reply_dst_ip,
                    reply_dst_port,
                    protocol,
                    repl_bytes,
                    repl_packets,
                    repl_rate,
                    repl_fasttrack_bytes,
                    repl_fasttrack_packets,
                    tcp_state,
                    timeout,
                    reply_src_geo_info['asn'],
                    reply_src_geo_info['asn_name'],
                    reply_src_geo_info['country'],
                    reply_src_geo_info['country_name'],
                    reply_src_geo_info['city'],
                    reply_src_geo_info['latitude'],
                    reply_src_geo_info['longitude'],
                    reply_dst_geo_info['asn'],
                    reply_dst_geo_info['asn_name'],
                    reply_dst_geo_info['country'],
                    reply_dst_geo_info['country_name'],
                    reply_dst_geo_info['city'],
                    reply_dst_geo_info['latitude'],
                    reply_dst_geo_info['longitude'],
                    is_private
                ))
            except (ValueError, TypeError) as e:
                print(f"[{time.ctime()}] Skipping record due to error: {e}", file=sys.stderr)
                continue

        if records_to_insert:
            print(f"[{time.ctime()}] Pushing {len(records_to_insert)} records to ClickHouse...")
            client = Client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD, database=CLICKHOUSE_DB)
            client.execute(f"INSERT INTO {CLICKHOUSE_TABLE} VALUES", records_to_insert)
            print(f"[{time.ctime()}] Successfully pushed {len(records_to_insert)} records.")
        else:
            print(f"[{time.ctime()}] No records to push.")

    except requests.exceptions.RequestException as e:
        print(f"[{time.ctime()}] Error connecting to MikroTik REST API: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[{time.ctime()}] An unexpected error occurred: {e}", file=sys.stderr)


def main():
    print("MikroTik to ClickHouse data pusher started.")

    # Check clickhouse connection & Create DB if needed
    try:
        # Connect to 'default' database first to ensure target DB exists
        client = Client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD)
        client.execute("SELECT 1")
        print("Successfully connected to ClickHouse (default).")
        
        client.execute(f"CREATE DATABASE IF NOT EXISTS {CLICKHOUSE_DB}")
        print(f"Database '{CLICKHOUSE_DB}' verified/created.")
        
        # Now connect to the specific database
        client = Client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD, database=CLICKHOUSE_DB)
        
        # Automatically create table if not exists using the global variable
        client.execute(create_table)
        print("Database schema verified.")

    except Exception as e:
        print(f"Error initializing ClickHouse: {e}", file=sys.stderr)
        sys.exit(1)
    
    roul.thread.start("update_bgptools", 86400, roul.asn.update)
    roul.thread.start("update_geoip2", 86400, load_geoip_db)

    while roul.asn.UPDATED_AT == 0:
        time.sleep(1)

    roul.thread.start("scrape_and_push", SCRAPE_INTERVAL, collect_and_push_metrics)

    while True:
        time.sleep(3600)

create_table = f"""
CREATE TABLE IF NOT EXISTS {CLICKHOUSE_TABLE} (
    current_time           DateTime,

    -- 각 연결에 부여하는 SHA-256 해시
    connection_id          FixedString(32),

    -- 트래픽 주소 및 포트 필드
    src_ip                 IPv4,
    src_port               UInt16,
    dst_ip                 IPv4,
    dst_port               UInt16,

    -- 기타 필드들
    protocol               LowCardinality(String),
    bytes                  UInt64,
    packets                UInt64,
    rate                   UInt64,
    fasttrack_bytes        UInt64,
    fasttrack_packets      UInt64,
    tcp_state              LowCardinality(String),
    timeout                UInt32,

    -- 지리 정보
    src_asn                UInt32,
    src_asn_name           LowCardinality(String),
    src_country            LowCardinality(FixedString(2)),
    src_country_name       LowCardinality(String),
    src_city               String,
    src_latitude           Int32,
    src_longitude          Int32,
    dst_asn                UInt32,
    dst_asn_name           LowCardinality(String),
    dst_country            LowCardinality(FixedString(2)),
    dst_country_name       LowCardinality(String),
    dst_city               String,
    dst_latitude           Int32,
    dst_longitude          Int32,
    
    -- 추가된 필드
    is_private             UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(current_time)
ORDER BY (current_time, connection_id, src_ip, dst_ip);
"""

if __name__ == '__main__':
    main()