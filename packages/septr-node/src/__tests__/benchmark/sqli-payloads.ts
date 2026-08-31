import type { BenchmarkPayload } from "../benchmark.test"

export const sqliPayloads: BenchmarkPayload[] = [
  // UNION-based
  { input: "1 UNION SELECT * FROM users", expect: true, source: "Basic UNION SELECT" },
  { input: "1 UNION SELECT username, password FROM admins--", expect: true, source: "UNION with columns" },
  { input: "' UNION SELECT null, @@version, null--", expect: true, source: "UNION version probe" },

  // OR 1=1 (classic auth bypass)
  { input: "' OR 1=1 --", expect: true, source: "Classic auth bypass" },
  { input: "admin' OR '1'='1", expect: true, source: "OR 1=1 quote variant" },
  { input: "1' OR '1'='1' --", expect: true, source: "OR 1=1 with dashes" },
  { input: "username = 'admin' OR 'admin' = 'admin'", expect: true, source: "OR true comparison" },

  // Destructive
  { input: "DROP TABLE users", expect: true, source: "DROP TABLE" },
  { input: "DROP TABLE IF EXISTS credentials", expect: true, source: "DROP IF EXISTS" },
  { input: "INSERT INTO users VALUES ('hacker', 'pw')", expect: true, source: "INSERT INTO" },
  { input: "DELETE FROM users WHERE id=1", expect: true, source: "DELETE FROM" },
  { input: "ALTER TABLE users ADD COLUMN admin BIT", expect: true, source: "ALTER TABLE" },
  { input: "ALTER TABLE users DROP COLUMN password_hash", expect: true, source: "ALTER TABLE DROP" },

  // Execution
  { input: "1; EXEC('xp_cmdshell dir')--", expect: true, source: "EXEC dynamic SQL" },
  { input: "EXECUTE('sp_addlogin')", expect: true, source: "EXECUTE dynamic SQL" },

  // Comment injection
  { input: "admin'--", expect: true, source: "SQL comment dash" },
  { input: "admin'/* comment */", expect: true, source: "SQL block comment" },
  { input: "' OR 1=1 /* test */", expect: true, source: "Comment in injection" },

  // Time-based blind
  { input: "1; SELECT pg_sleep(5)--", expect: true, source: "pg_sleep PostgreSQL" },
  { input: "1' AND pg_sleep(10) --", expect: true, source: "pg_sleep with AND" },
  { input: "1; WAITFOR DELAY '0:0:5'--", expect: true, source: "WAITFOR DELAY MSSQL" },
  { input: "1 OR WAITFOR DELAY '00:00:10'--", expect: true, source: "WAITFOR variant" },
  { input: "1 AND BENCHMARK(500000, MD5('test'))", expect: true, source: "BENCHMARK MySQL" },

  // Information gathering
  { input: "1 AND 1=CONVERT(int, (SELECT top 1 table_name FROM information_schema.tables))", expect: true, source: "INFORMATION_SCHEMA" },
  { input: "' UNION SELECT table_name FROM information_schema.tables--", expect: true, source: "INFORMATION_SCHEMA + UNION" },
  { input: "1 INTO OUTFILE '/tmp/evil.txt'", expect: true, source: "INTO OUTFILE" },

  // Multiple patterns
  { input: "1 UNION SELECT *; DROP TABLE users; --", expect: true, source: "Multiple SQLi patterns" },

  // Safe — should NOT trigger
  { input: "hello world", expect: false, source: "Safe text" },
  { input: "SELECT name FROM users", expect: false, source: "Safe SELECT" },
  { input: "", expect: false, source: "Empty string" },
  { input: "What is the capital of France?", expect: false, source: "Normal question" },
  { input: "John Doe", expect: false, source: "Simple name" },

  // Exploit-DB webapp PoCs (real strings from the exploit archive, CVE-referenced)
  { input: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", expect: true, source: "EDB error-based MySQL (CVE-2019-14772 class)" },
  { input: "?id=1 union select 1,group_concat(table_name) from information_schema.tables-- -", expect: true, source: "EDB UNION information_schema dump" },
  { input: "admin'--", expect: true, source: "EDB auth-bypass comment injection (CVE-2018-15133 class)" },
  { input: "1' OR '1'='1' /*", expect: true, source: "EDB comment-wrapped OR 1=1" },
  { input: "' UNION ALL SELECT NULL,NULL,CONCAT(user,0x3a,pass) FROM mysql.user-- -", expect: true, source: "EDB MySQL credential dump shape" },
]
