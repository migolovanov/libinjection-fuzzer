#  libinjection fuzzer
This tool is supposed to fuzz MariaDB/MSSQL/MySQL/PostgreSQL/Oracle database query to find libinjection bypasses.
Related articles:

[libinjection: fuzz to bypass](https://waf.ninja/libinjection-fuzz-to-bypass/)

[Part 2. libinjection: different databases fuzzing](https://waf.ninja/libinjection-different-databases-fuzzing/)

## Help
```
# python fuzzer.py -h
usage: fuzzer.py [-h] [-t {mysql,mariadb,mssql,pgsql,oracle}] -q QUERY -p
                 PAYLOAD -c CHARS [-u USER] [--password PASSWORD] -d DB
                 [-o OUT] [--log-all] [--check CHECK] [--threads THREADS]

libinjection fuzzer MariaDB, MSSQL, MySQL, PostgreSQL and Oracle databases

optional arguments:
  -h, --help            show this help message and exit
  -t {mysql,mariadb,mssql,pgsql,oracle}, --type {mysql,mariadb,mssql,pgsql,oracle}
                        Database type: mysql, mssql
  -q QUERY, --query QUERY
                        Query to fuzz
  -p PAYLOAD, --payload PAYLOAD
                        Payload to use
  -c CHARS, --chars CHARS
                        Characters to fuzz
  -u USER, --user USER  Database user
  --password PASSWORD   Database user
  -d DB, --db DB        Database name
  -o OUT, --out OUT     Filename pattern (default: log)
  --log-all
  --check CHECK         Check value
```

## Usage example
```
python fuzzer.py -t pgsql -u pt -d test --log-all -q "select * from users where id='1{}'" -c " \"#\$%&()*+,-./1:;<=>?@[\]^_\`a{|}~!" -p "' + {} union select 'a',version() -- 1"
```
