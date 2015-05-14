# 1) Pulls files from remote machines and consolidates them into a local directory.
# 2) Prefixes the files with the hostname so the filenames don't conflict in
# in the local directory.
#
# Example:
# python gatherlogs.py --hosts IP1,IP22 --src /var/tmp/user* --local /tmp/bucket


import argparse
import subprocess
import os
import sys
import tempfile


def scp(host, path, local=".", port=22, user="root", password=None):
    scp_cmd = "scp -P %s %s@%s:%s %s" % (port, user, host, path, local)
    if args.debug:
        print "DEBUG::: " + scp_cmd
    proc = subprocess.Popen(scp_cmd, shell=True, stdout=subprocess.PIPE)
    return proc.stdout.readlines()


def prefix_files(path, prefix=""):

    proc = subprocess.Popen("ls %s" % path, shell=True, stdout=subprocess.PIPE)
    for f in proc.stdout.readlines():
        f = f.rstrip()
        cmd = "mv %s/%s %s/%s%s" % (path, f, path, prefix, f)
        if args.debug:
            print "DEBUG::: " + cmd
        os.system(cmd)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Gather logs")
    parser.add_argument('--src', dest="src", type=str, required=True, help="Location on the remote host")
    parser.add_argument('--local', dest="local", type=str, required=True, help="Local directory target (must exist)")
    parser.add_argument('--prefix', dest="local", type=str, default="", help="not-used")
    parser.add_argument('--hosts', dest='hosts', type=str, required=True, help="Comma separated lists of IPs or hostnames. (e.g. ip1,ip2,ip3)")
    parser.add_argument('--debug', dest='debug', action='store_true', help="debugging output")
    parser.add_argument('--silent', dest='silent', type=str, help="not-used")
    # parser.add_argument('--noclean', dest='noclean', action='store_true', help="Don't delete temporary directories")
    parser.add_argument('--dayskeep', dest='dayskeep', type=str, help="Keep N days of logs. Parses date embedded in filename in format 2015-02-13, (e.g. user-logs-2015-02-13.log)")

    args = parser.parse_args()

    if not os.path.isdir(args.local):
        print args.local + " doesn't exist."
        sys.exit(1)

    for host in args.hosts.split(","):
        tmpdir = tempfile.mkdtemp()
        print "Copying logs from %s to %s" % (host, tmpdir)
        scp(host, args.src, local=tmpdir)
        print "Moving to %s" % (args.local)
        prefix_files(tmpdir, host + "-")
        os.system("mv %s/* %s" % (tmpdir, args.local))
        os.rmdir(tmpdir)
