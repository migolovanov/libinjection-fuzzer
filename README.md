#  libinjection fuzzer
This tool is supposed to fuzz MySQL database query to find libinjection bypasses.

## Help
```
# python fuzzer.py -h
usage: fuzzer.py [-h] [-t {mysql,mariadb,mssql,pgsql,oracle}] -q QUERY -p
                 PAYLOAD -c CHARS [-u USER] [--password PASSWORD] -d DB
                 [-o OUT] [--log-all] [--check CHECK] [--threads THREADS]

libinjection fuzzer for MySQL database

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
  --threads THREADS     Set threads number (default: 4)
```

## Usage example
```
python fuzzer.py -t pgsql -u pt -d test --log-all -q "select * from users where id='1{}'" -c " \"#\$%&()*+,-./1:;<=>?@[\]^_\`a{|}~!" -p "' + {} union select 'a',version() -- 1"
```
