# 1) Pulls files from remote machines and consolidates them into a local directory.
# 2) Prefixes the files with the hostname so the filenames don't conflict in
# in the local directory.

import argparse
import os
import sys
import re
import datetime
# pip install paramiko scp
from paramiko import SSHClient, AutoAddPolicy, SFTPClient, Transport
from scp import SCPClient
from os.path import expanduser
import yaml

args = []
CREDS = {}


def listdir(hostname, path="/var/tmp", filter="", port=1035, username="", password=""):
    '''
        paramiko sftp listdir wrapper, with option to filter files
    '''
    # Paramiko client configuration

    t = Transport((hostname, port))
    t.connect(username=username, password=password)
    sftp = SFTPClient.from_transport(t)

    try:
        rex = re.compile(filter)
    except:
        print "Invalid regular expression: " + filter
        sys.exit(1)

    return [x for x in sftp.listdir(path) if rex.match(x)]


def _reduce_to_date(fname):
    '''
    Filename that hs YYYY-MM-DD will be returned as a date object
    '''
    m = re.match('.*(\d{4}-\d{2}-\d{2}).*', fname)
    if m and m.group(1):
        ymd = map(int, m.group(1).split("-"))
        return datetime.date(*ymd)
    else:
        return datetime.date.today()  # Default to today if a timestamp in the file isn't found.


def filter_days_old(alist, days=365):
    '''
    Array of filenames with YYYY-MM-DD in the filename are filtered
    '''
    d_keepnewer = [f for f in alist if _reduce_to_date(f) > (datetime.date.today() - datetime.timedelta(days=days))]
    return d_keepnewer


def progress(filename, size, sent):
    if args.verbose:
        print filename + " " + str(size) + " " + str(sent)


def parse_args():
    parser = argparse.ArgumentParser(description="Gather logs")
    parser.add_argument('--src', dest="src", type=str, required=True, help="Valid directory at remote location. No wildcards.")
    parser.add_argument('--local', dest="local", type=str, required=True, help="Local directory target (must exist)")
    parser.add_argument('--filter', dest="filter", type=str, default="", help="Filter files based on valid regular expression (e.g. '.*user-action.*'")
    parser.add_argument('--hosts', dest='hosts', type=str, required=True, help="Comma separated lists of IPs or hostnames. (e.g. ip1,ip2,ip3)")
    parser.add_argument('--debug', dest='debug', action='store_true', help="debugging output")
    parser.add_argument('--username', dest='username', help="Or put credentials in ~/.gatherlogs.creds in YAML format, (e.g.) {password: 'blah[]\', username: root}")
    parser.add_argument('--password', dest='password', help="Use single quotes if password contains a backlash")
    parser.add_argument('--verbose', dest='verbose', action='store_true', help="Show scp progress")
    parser.add_argument('--days', dest='days', type=int, default=365, help="Get N days of logs, if timestamp exists (e.g. user-logs-2015-02-13.log)")
    parser.add_argument('--port', dest='port', type=int, default=1035, help="SCP port. Default of 1035.")
    global args
    args = parser.parse_args()


def validate_args():
    if not os.path.isdir(args.local):
        print args.local + " doesn't exist."
        sys.exit(1)

    # Load creds from a yaml format.
    if args.username is None and args.password is None:
        stream = file(os.path.join(expanduser("~"), '.gatherlogs.creds'), 'r')
        global CREDS
        CREDS = yaml.load(stream)

if __name__ == "__main__":

    parse_args()
    validate_args()

    ssh = SSHClient()
    # ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    total = 0
    # Host argument are comma-separated (no spaces)
    for host in args.hosts.split(","):
        ssh.connect(host, port=args.port, username=CREDS['username'], password=CREDS['password'])
        # pass-through sanitize to allow wildcards.
        scp = SCPClient(ssh.get_transport(), sanitize=lambda x: x, progress=progress)

        print "Copying logs from %s to %s" % (host, args.local)

        for f in filter_days_old(listdir(host, port=args.port,
                                         path=args.src, filter=args.filter,
                                         username=CREDS['username'], password=CREDS['password']),
                                 args.days):
            scp.get(os.path.join("/var/tmp/", f), os.path.join(args.local, "{}-{}".format(host, f)))
            total = total + 1

    print "Files: {}".format(total)
