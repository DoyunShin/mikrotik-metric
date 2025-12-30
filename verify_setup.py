import time
import sys
import subprocess
from clickhouse_driver import Client
import app

# DB 접속 정보 (app.py 설정 사용)
HOST = app.CLICKHOUSE_HOST
PORT = app.CLICKHOUSE_PORT
USER = app.CLICKHOUSE_USER
PASS = app.CLICKHOUSE_PASSWORD
TARGET_DB = app.CLICKHOUSE_DB
TARGET_TABLE = app.CLICKHOUSE_TABLE

def wait_for_clickhouse():
    print("Waiting for ClickHouse to be ready...")
    for i in range(30):
        try:
            # Connect without specifying DB to just check connectivity
            client = Client(host=HOST, port=PORT, user=USER, password=PASS)
            client.execute("SELECT 1")
            print("ClickHouse is ready (connectivity established)!")
            return True
        except Exception as e:
            time.sleep(1)
            print(f"Connection failed: {e}")
    return False

def check_db_exists(db_name):
    try:
        client = Client(host=HOST, port=PORT, user=USER, password=PASS)
        exists = client.execute(f"SELECT count() FROM system.databases WHERE name = '{db_name}'")
        return exists[0][0] == 1
    except Exception as e:
        print(f"Error checking DB: {e}")
        return False

def check_table_exists(db_name, table_name):
    try:
        client = Client(host=HOST, port=PORT, user=USER, password=PASS)
        exists = client.execute(f"EXISTS TABLE {db_name}.{table_name}")
        return exists[0][0] == 1
    except Exception as e:
        return False

def get_row_count(db_name, table_name):
    try:
        client = Client(host=HOST, port=PORT, user=USER, password=PASS, database=db_name)
        result = client.execute(f"SELECT count() FROM {table_name}")
        return result[0][0]
    except Exception:
        return 0

def run_test():
    if not wait_for_clickhouse():
        print("Failed to connect to ClickHouse.")
        sys.exit(1)

    # 1. 초기 상태 확인
    print(f"\n[Step 1] Checking initial state...")
    if check_db_exists(TARGET_DB):
        print(f"Note: Database '{TARGET_DB}' exists. Checking table...")
        if check_table_exists(TARGET_DB, TARGET_TABLE):
            print(f"Warning: Table '{TARGET_TABLE}' already exists. Dropping for clean test.")
            Client(host=HOST, port=PORT, user=USER, password=PASS).execute(f"DROP DATABASE {TARGET_DB}")
            print("Dropped existing database.")
    
    # 2. app.py 실행
    print(f"\n[Step 2] Running 'app.py' for 150 seconds (Performance Test)...")
    proc = subprocess.Popen([sys.executable, 'app.py'])
    
    try:
        time.sleep(150)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    
    print("Stopped 'app.py'.")

    # 3. 결과 검증
    print(f"\n[Step 3] Verifying Setup...")
    count = get_row_count(TARGET_DB, TARGET_TABLE)
    print(f"Data Rows: {count}")
    
    if count > 0:
        print("\n=== TEST PASSED ===")
    else:
        print("\n=== TEST FAILED (No Data) ===")

if __name__ == "__main__":
    run_test()
