#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import argparse
import pylibinjection
import mysql.connector
from mysql.connector import errorcode


def colorize(color, text):
    if color == 'red':
        return ''.join(['\033[1;31m', text, '\033[1;m'])
    elif color == 'green':
        return ''.join(['\033[1;32m', text, '\033[1;m'])
    elif color == 'blue':
        return ''.join(['\033[1;34m', text, '\033[1;m'])
    else:
        return text


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description='libinjection fuzzer for MySQL database')
    parser.add_argument('-q', '--query',
                        dest='query',
                        help='Query to fuzz',
                        required=True)
    parser.add_argument('-p', '--payload',
                        dest='payload',
                        help='Payload to use',
                        required=True)
    parser.add_argument('-c', '--chars',
                        dest='chars',
                        help='Characters to fuzz',
                        required=True)
    parser.add_argument('-u', '--user',
                        dest='user',
                        help='Database user',
                        required=True)
    parser.add_argument('--password',
                        dest='password',
                        help='Database user',
                        default='')
    parser.add_argument('-d', '--db',
                        dest='db',
                        help='Database name',
                        required=True)
    parser.add_argument('-o', '--out',
                        dest='out',
                        help='Filename pattern (default: log)',
                        default="log")
    parser.add_argument('--log-all',
                        dest='log_all',
                        action='store_true')
    return parser.parse_args()


def get_next(string, args):
    if len(string) <= 0:
        string.append(args.chars[0])
    else:
        string[0] = args.chars[
            (args.chars.index(string[0]) + 1) % len(args.chars)]
        if args.chars.index(string[0]) is 0:
            return list(string[0]) + get_next(string[1:], args)
    return string


def main(cnx, args):
    sequence = list()
    fingerprints = list()
    if args.log_all:
        file_log = open("{}_all.txt".format(args.out), "w")
    while True:
        file_good = open("{}_good.txt".format(args.out), "a")
        if args.log_all:
            file_bad = open("{}_bad.txt".format(args.out), "a")
        sequence = get_next(sequence, args)
        item = ''.join(reversed(sequence))
        payload = args.payload.format(item)
        try:
            cursor = cnx.cursor()
            cursor.execute(args.query.format(payload))
            rows = cursor.fetchall()
            sqli = pylibinjection.detect_sqli(payload)
            msg = "Fingerprint: {} Query: {} Result: {}".format(
                sqli["fingerprint"], args.query.format(payload), rows)
            if len(rows) > 0:
                if sqli["sqli"]:
                    print colorize("red", "[BLOCKED] {}".format(msg))
                    if args.log_all:
                        file_bad.write("[BLOCKED] {}\n".format(msg))
                else:
                    if sqli["fingerprint"] in fingerprints:
                        print colorize("blue", "[PASS][DUP] {}".format(msg))
                    else:
                        print colorize("green", "[PASS][NEW] {}".format(msg))
                        file_good.write("[PASS] {}\n".format(msg))
                        fingerprints.append(sqli["fingerprint"])
        except BaseException:
            if args.log_all:
                file_log.write(
                    "[ERROR] Query: {}\n".format(
                        args.query.format(payload)))
            continue


if __name__ == "__main__":
    args = parse_cli_args()
    try:
        cnx = mysql.connector.connect(
            user=args.user,
            password=args.password,
            database=args.db)
        main(cnx, args)
        cnx.close()
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print(
                colorize(
                    "red",
                    "[ERROR] Something is wrong with your user name or password"))
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print(colorize("red", "[ERROR] Database does not exist"))
        else:
            print(colorize("red", "[ERROR] {}".format(err)))
    else:
        cnx.close()
