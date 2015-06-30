#! /usr/bin/python

# Original Example code to output account security config
# __author__ = 'Greg Roth', from aws conference.
#
# Refactored code into functional components.
# Modified to scan multiple regions, and be easily run as a cron job.
# Can Emails diffs to SNS topic.
#
# Example Usage as a Cron:
# 0,15,30,45 * * * * cd <yourdir>;python SecAudit.py -o log.txt --sns <your topic>
#
# Run the above every 15 mins or as desired and you will recieve a diff if your
# security profile ever changes.
#
# Tech Notes:
# Stores reports in logs/
# If you give -o log.txt, the filename will have a timestamp pre-pended to it, e.g.
# 2015-03-08_055740_log.txt. This is necessary to compare the most recent logs.
#
# 0,15,30,45 * * * * cd /home/ec2-user;python /home/ec2-user/SecAudit.py --sns arn:aws:sns:us-west-2:nono:nono -o logs.tx

__author__ = 'Brian Fleming'

from os import mkdir
import sys
import boto
import urllib
import hashlib
import argparse
import re
from datetime import datetime
import difflib
from os import listdir
from os.path import isfile, join
import boto.sns
import boto.sqs
import boto.ec2
import time

LOGDIR = "logs/"
REGIONS = ['us-east-1', 'us-west-2', 'us-west-2', 'ap-northeast-1']


def _reduce_to_date(fname):
    '''
    Filename that hs YYYY-MM-DD will be returned as a date object
    '''
    m = re.match('.*(\d{4}-\d{2}-\d{2}_\d{2}\d{2}\d{2}).*', fname)
    if m and m.group(1):
        # ymd = map(int, m.group(1).split("-"))
        return datetime.strptime(m.group(1), "%Y-%m-%d_%H%M%S")
    else:
        return datetime.today()  # Default to today if a timestamp in the file isn't found.


def diff_recent_logs():
    import difflib
    from os import listdir
    from os.path import isfile, join
    lfiles = [f for f in listdir(LOGDIR) if isfile(join(LOGDIR, f))]
    sf = sorted(lfiles, key=_reduce_to_date)
    last2 = sf[-2:]
    diff = difflib.unified_diff(open(LOGDIR + last2[1]).readlines(), open(LOGDIR + last2[0]).readlines())

    ldiff = list(diff)
    diffstr = '\n'.join(ldiff)
    import boto.sns
    if len(ldiff) > 0:
        if args.sns:
            sns = boto.sns.connect_to_region('us-west-2')
            sns.publish(args.sns, message=diffstr, subject="Security Notice!")
    else:
        print "It's fine"


def debug(str):
    if args.debug:
        print str


def verbose(str):
    if args.verbose or args.debug:
        print str


def sha256(m):
    return hashlib.sha256(m).hexdigest()


def config_line(header, name, detail, data):
    return header + ", " + name + ", " + detail + ", " + data


def config_line_policy(header, name, detail, data):
    verbose("===== " + header + ":  " + name + ":  " + detail + "=====")
    verbose(data)
    verbose("=========================================================")
    return config_line(header, name, detail, sha256(data))


def output_lines(lines):
    if args.output:
        f = open(args.output, "a")
        for l in lines:
            f.write(l + "\n")

        f.close()

    else:
        lines.sort()
        for line in lines:
            print line


def get_iam_summary():
    iam = boto.connect_iam(security_token=security_token)
    verbose("Getting account summary:")
    summary = iam.get_account_summary()
    debug(summary)
    return [config_line("iam:accountsummary", "AccountMFAEnabled", "", str(summary["AccountMFAEnabled"]))]


def get_iam_user_info():
    # IAM user info
    iam = boto.connect_iam(security_token=security_token)
    verbose("Getting IAM user info:")
    user_info = []
    users = iam.get_all_users().list_users_response.list_users_result.users
    debug(users)
    for user in users:
        verbose("User: " + user.user_name)
        # User policies
        policies = iam.get_all_user_policies(user.user_name)
        policies = policies.list_user_policies_response.list_user_policies_result.policy_names
        for policy_name in policies:
            policy = iam.get_user_policy(user.user_name, policy_name) \
                .get_user_policy_response.get_user_policy_result.policy_document
            policy = urllib.unquote(policy)
            user_info.append(config_line_policy("iam:userpolicy", user.user_name, policy_name, policy))

        # access keys
        access_keys = iam.get_all_access_keys(user.user_name)
        access_keys = access_keys.list_access_keys_response.list_access_keys_result.access_key_metadata
        for access_key in access_keys:
            user_info.append(
                config_line("iam:accesskey", access_key.user_name, access_key.status, access_key.access_key_id))

        # group membership
        groups = iam.get_groups_for_user(user.user_name)
        groups = groups.list_groups_for_user_response.list_groups_for_user_result.groups
        for group in groups:
            user_info.append(config_line("iam:useringroup", user.user_name, "", group.group_name))

    return sorted(user_info)


def get_iam_groups():
    # IAM groups
    iam = boto.connect_iam(security_token=security_token)
    verbose("Getting IAM group info:")
    group_policy = []
    groups = iam.get_all_groups().list_groups_response.list_groups_result.groups
    for group in groups:
        verbose("Group " + group.group_name)
        # Policies attached to groups
        policies = iam.get_all_group_policies(group.group_name)
        policies = policies.list_group_policies_response.list_group_policies_result.policy_names
        for policy_name in policies:
            policy = iam.get_group_policy(group.group_name, policy_name)
            policy = policy.get_group_policy_response.get_group_policy_result.policy_document
            policy = urllib.unquote(policy)
            group_policy.append(config_line_policy("iam:grouppolicy", group.group_name, policy_name, policy))

    return sorted(group_policy)


def get_iam_roles():
    # IAM Roles
    iam = boto.connect_iam(security_token=security_token)
    verbose("Getting IAM role info:")
    role_policy = []
    roles = iam.list_roles().list_roles_response.list_roles_result.roles
    for role in roles:
        verbose("Role: " + role.role_name)
        # Policy controling use of the role (always present)
        assume_role_policy = role.assume_role_policy_document
        assume_role_policy = urllib.unquote(assume_role_policy)
        role_policy.append(config_line_policy("iam:assumerolepolicy", role.role_name, role.arn, assume_role_policy))

        # Policies around what the assumed role can do
        policies = iam.list_role_policies(role.role_name)
        policies = policies.list_role_policies_response.list_role_policies_result.policy_names
        for policy_name in policies:
            policy = iam.get_role_policy(role.role_name, policy_name)
            policy = policy.get_role_policy_response.get_role_policy_result.policy_document
            policy = urllib.unquote(policy)
            role_policy.append(config_line_policy("iam:rolepolicy", role.role_name, policy_name, policy))
        debug(policies)

    return sorted(role_policy)


def get_s3_bucket_policy(region):
    # S3 bucket policies
    verbose("Getting S3 bucket policies:")
    s3 = boto.s3.connect_to_region(region)
    bucket_info = []
    buckets = s3.get_all_buckets()
    for bucket in buckets:
        try:
            policy = bucket.get_policy()
            bucket_info.append(config_line_policy(region + " s3:bucketpolicy", bucket.name, "", policy))
        except boto.exception.S3ResponseError as e:
            bucket_info.append(config_line(region + " s3:bucketpolicy", bucket.name, "", e.code))

    return sorted(bucket_info)


def get_sqs_policy(region):
    # SQS queue policies
    verbose("Getting SQS queue policies:")
    sqs = boto.sqs.connect_to_region(region)
    queue_info = []
    queues = sqs.get_all_queues()
    for queue in queues:
        try:
            policy = sqs.get_queue_attributes(queue, "Policy")["Policy"]
            queue_info.append(config_line_policy(region + " sqs:queuepolicy", queue.url, "", policy))
        except KeyError:
            queue_info.append(config_line(region + " sqs:queuepolicy", queue.url, "", "NoPolicy"))

    return sorted(queue_info)


def get_sns_topics(region):
    # SNS topic policies
    verbose("Getting SNS topic policies:")
    sns = boto.sns.connect_to_region(region)
    topic_info = []
    topics = sns.get_all_topics()
    topics = topics["ListTopicsResponse"]["ListTopicsResult"]["Topics"]
    for topic in topics:
        policy = sns.get_topic_attributes(topic["TopicArn"])
        policy = policy["GetTopicAttributesResponse"]["GetTopicAttributesResult"]["Attributes"]["Policy"]
        topic_info.append(config_line_policy(region + " sns:topicpolicy", topic["TopicArn"], "", policy))

    return sorted(topic_info)


def get_security_groups(region):
    # EC2 security groups
    sg_info = []
    ec2 = boto.ec2.connect_to_region(region)
    groups = ec2.get_all_security_groups()
    for group in groups:
        for rule in group.rules:
            for grant in rule.grants:
                sg_info.append(config_line(region + " ec2:security_group", group.name, str(rule), str(grant)))

    return sorted(sg_info)


# Requires EC2 Role or creds in your ~/.boto file that allows
# access to get these things.
def gen_report():

    report = []
    report.extend(get_iam_summary())
    report.extend(get_iam_user_info())
    report.extend(get_iam_groups())
    report.extend(get_iam_roles())

    for region in REGIONS:
        report.extend(get_s3_bucket_policy(region))
        report.extend(get_sqs_policy(region))
        report.extend(get_sns_topics(region))
        report.extend(get_security_groups(region))

    return [str(c) + '\n' for c in report]


# Return the n'th most recent file. Requires the filename prefix be
# have a time stamp. e.g. 2015-03-08_055740_log.txt
def get_last_tstamp_file(ldir, lastn=1):
    lfiles = [f for f in listdir(ldir) if isfile(join(ldir, f))]
    sf = [join(ldir, f) for f in sorted(lfiles, key=_reduce_to_date)]

    if len(sf) > 0:
        return sf[-lastn:]
    else:
        return []


def save_report(report, filename):
    f = open(filename, "a")
    for l in report:
        f.write(l)
    f.close()


def gen_and_diff(logdir="."):

    # Get previous report
    lfiles = get_last_tstamp_file(logdir)
    if len(lfiles) > 0:
        f = lfiles[0]
    else:
        print "No previous log files to compare."
        report = gen_report()
        if args.outfile:
            print "Writing first log file."
            save_report(report, args.outfile)
        else:
            print report

        sys.exit(0)

    print "Comparing to " + str(f)

    # Load previous report
    preport = open(f).readlines()

    # Gen current report
    creport = gen_report()

    diff = difflib.unified_diff(preport, creport, n=1)

    ldiff = list(diff)
    if len(ldiff) > 0:

        print "Found diffs.  Sending notification."
        sns = boto.sns.connect_to_region('us-west-2')
        diffstr = ''.join(ldiff)
        if args.sns:
            sns.publish(args.sns, message=diffstr, subject="Security Notice!")
        else:
            print diffstr

        if args.outfile:
            save_report(creport, args.outfile)

        return ldiff
    else:
        return None


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='outputs security configuration of an AWS account')
    parser.add_argument('-a', '--access_key_id', required=False, help='access key id. Overrides ~/.boto')
    parser.add_argument('-k', '--secret_access_key', required=False, help='secret access key. \
Overrides ~/.boto')
    # Not tested
    parser.add_argument('-t', '--security_token', help='security token (for use with temporary security credentials)')
    parser.add_argument('-r', '--role', help='arn of role to assume')
    parser.add_argument('-s', '--sns', type=str, help='Send diff report to this arn::sns topic. \
Assumes us-west-2 region.')
    parser.add_argument('-v', '--verbose', action="store_true", help='enable verbose mode')
    parser.add_argument('-d', '--debug', action="store_true", help='enable debug mode')
    parser.add_argument('-o', '--outfile', type=str, default="", help='Timestamp will be prefixed automatically')
    parser.add_argument('-p', '--printo', type=str, default="", help='Print report only')

    args = parser.parse_args()

    if args.access_key_id and args.secret_access_key:
        # access_key_id = args.access_key_id
        # secret_access_key = args.secret_access_key
        # assumed_role = sts.assume_role(args.role, "SecAudit")
        boto.config.set('Credentials', 'aws_access_key_id', value=args.access_key_id)
        boto.config.set('Credentials', 'aws_secret_access_key', value=args.secret_access_key)

    security_token = args.security_token
    try:
        mkdir(LOGDIR)
    except:
        pass

    if args.outfile:
        args.outfile = LOGDIR + time.strftime("%Y-%m-%d_%H%M%S") + "_" + args.outfile

    if args.role:
        sts = boto.connect_sts()
        assumed_role = sts.assume_role(args.role, "SecAudit")
        boto.config.set('Credentials', 'aws_access_key_id', value=assumed_role.credentials.access_key)
        boto.config.set('Credentials', 'aws_secret_access_key', value=assumed_role.credentials.secret_key)
        # This one needs to be checked, I am only guessing it is aws_security_token
        boto.config.set('Credentials', 'aws_security_token', value=assumed_role.credentials.session_token)
        # security_token = args.security_token

    if args.printo:
        print gen_report()

    # Let's go!
    gen_and_diff(logdir=LOGDIR)
