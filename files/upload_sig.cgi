#!/usr/bin/python2
#
# CGI script to handle file updates for the rpms CVS repository. There
# is nothing really complex here other than tedious checking of our
# every step along the way...
#
# Written for Fedora, modified to suit CentOS Infrastructure.
# Modified by Howard Johnson <merlin@merlinthp.org> 2014
# Modified by Fabian Arrotin <fabian.arrotin@arrfab.net> 2020 (FASJSON calls for group membership)
# Modified by Leonardo Rossetti <lrossett@redhat.com0> 2022 (lookaside cache structure)
# License: GPL

#
# centos' lookaside is a bit differently laid out to fedora's.
# centos uses a <package>/<branch>/<sha1sum> scheme.
#
# The upload.cgi gets called with the following arguments:
#   name - package (git repo) name
#   branch - branch name
#   sha1sum - SHA1 checksum of the file
#   file - the file to upload (optional)
#
# With only the first three args, the script runs in check mode.
# With the fourth too, it operates in upload mode.
#

import os
import sys
import cgi
import tempfile
import syslog
import smtplib
import re
from ConfigParser import SafeConfigParser
import json
import requests
from requests_gssapi import HTTPSPNEGOAuth

from email import Utils
try:
    from email.mime.text import MIMEText
except ImportError:
    from email.MIMEText import MIMEText

import hashlib
sha1_constructor = hashlib.sha1


# Reading buffer size
BUFFER_SIZE = 4096

conf = SafeConfigParser()
conf.read(os.environ.get('LOOKASIDE_CFG_PATH', '/etc/lookaside.cfg'))


def is_sig_member(groups):
    return len([g for g in groups if g.startswith('sig')]) > 0


def stripwithquotes(thestring):
    return thestring.strip('\" \n')


def send_error(text):
    print 'Content-Type: text/plain'
    print
    print text
    sys.exit(1)


def check_auth(username, branchname=None, groupmemberships=None):
    if groupmemberships is None:
        groupmemberships = get_memberships(username)

    for group in groupmemberships:
        if group == conf.get('acls', 'push_superadmin_group'):
            return True

        if branchname is not None:
            if re.match(r'c\ds?-{0}.*'.format(group), branchname):
                print >>sys.stderr, "Matched {} against {}".format(group,
                                                                   branchname)
                return True

    # requires to be a sig member
    if is_sig_member(groupmemberships):
        return True

    return False


def get_memberships(username):
    os.environ['KRB5_CLIENT_KTNAME'] = conf.get('acls', 'fasjson_keytab')
    fasjson_url = conf.get('acls', 'fasjson_url')
    fasjson_full_url = '%s/v1/users/%s/groups/' % (fasjson_url,username)
    try:
      gssapi_auth = HTTPSPNEGOAuth(opportunistic_auth=True,mutual_authentication='OPTIONAL')
      results = requests.get(fasjson_full_url, auth=gssapi_auth) 
    except:
        print >>sys.stderr, "Error looking up group memberships. HTTP Error code {}".format(results.status_code)
        return None
      
    if results.status_code >= 400:
        print >>sys.stderr, "Error looking up group memberships. HTTP Error code {}".format(results.status_code)
        return None

    json_body = json.loads(results.text)
    group_list = []
    for group in json_body['result']:
      group_list.append(group['groupname'])
  
    return group_list


def check_form(form, var, exit_on_error=True):
    ret = form.getvalue(var, None)
    if ret is None:
        if not exit_on_error:
            return None
        send_error('Required field "%s" is not present.' % var)
    if isinstance(ret, list):
        send_error('Multiple values given for "%s". Aborting.' % var)
    return ret


def send_email(pkg, sha1, filename, username, branch=''):
    text = """A file has been added to the lookaside cache for %(pkg)s:

%(branch)s %(sha1)s  %(filename)s""" % locals()
    msg = MIMEText(text)
    sender_name = conf.get('mail', 'sender_name')
    sender_email = conf.get('mail', 'sender_email')
    sender = Utils.formataddr((sender_name, sender_email))
    recipient = conf.get('mail', 'recipient')
    msg['Subject'] = 'File %s uploaded to lookaside cache, branch %s by %s' % (
            filename, branch, username)
    msg['From'] = sender
    msg['To'] = recipient
    try:
        s = smtplib.SMTP(conf.get('mail', 'smtp_server'))
        s.sendmail(sender, recipient, msg.as_string())
    except:
        errstr = 'sending mail for upload of %s failed!' % filename
        print >> sys.stderr, errstr
        syslog.syslog(errstr)


def main():
    os.umask(002)

    username = os.environ.get('SSL_CLIENT_S_DN_CN', None)

    assert os.environ['REQUEST_URI'].split('/')[1] == 'sources'

    form = cgi.FieldStorage()
    name = check_form(form, 'name')
    branch = check_form(form, 'branch', exit_on_error=False)
    is_hash_format = branch is None

    # Search for the file hash, start with stronger hash functions
    if 'sha512sum' in form:
        checksum = check_form(form, 'sha512sum')
        hash_type = "sha512"

    elif 'md5sum' in form:
        # Fallback on md5, as it's what we currently use
        checksum = check_form(form, 'md5sum')
        hash_type = "md5"

    elif 'sha1sum' in form:
        checksum = check_form(form, 'sha1sum')
        hash_type = "sha1"
    else:
        send_error('Required checksum is not present.')

    if branch is None and not is_hash_format:
        send_error('Couldn\'t identify cache format.')

    action = None
    upload_file = None
    filename = None

    # Is this a submission or a test?
    # in a test, we don't get a file.
    if 'file' not in form:
        action = 'check'
        if is_hash_format:
            print >> sys.stderr, '[username=%s] Checking file status: NAME=%s HASH=%s SHA1SUM=%s' % (username, name, hash_type, checksum)
        else:
            print >> sys.stderr, '[username=%s] Checking file status: NAME=%s BRANCH=%s SHA1SUM=%s' % (username, name, branch, checksum)
    else:
        action = 'upload'
        upload_file = form['file']
        if not upload_file.file:
            send_error('No file given for upload. Aborting.')
        filename = os.path.basename(upload_file.filename)
        if is_hash_format:
            print >> sys.stderr, '[username=%s] Processing upload request: NAME=%s HASH=%s CHECKSUM=%s' % (username, name, hash_type, checksum)
        else:
            print >> sys.stderr, '[username=%s] Processing upload request: NAME=%s BRANCH=%s CHECKSUM=%s' % (username, name, branch, checksum)

    if is_hash_format:
        module_dir_args = [name, filename, hash_type, checksum]
        dest_file_args = [filename]
    else:
        module_dir_args = [name, branch]
        dest_file_args = [checksum]
    module_dir = os.path.join(conf.get('lookaside', 'cache_dir'), *module_dir_args)
    dest_file = os.path.join(module_dir, *dest_file_args)

    # if desired, make sure the user has permission to write to this branch
    if conf.getboolean('acls', 'do_acl'):
        if not check_auth(username, branch):
            print 'Status: 403 Forbidden'
            print 'Content-type: text/plain'
            print
            print 'You must connect with a valid certificate and have permissions on the appropriate branch to upload'
            sys.exit(0)

    # check that all directories are in place
    if not os.path.isdir(module_dir):
        try:
            os.makedirs(module_dir, 02775)
        except:
            print 'Status: 403 Forbidden'
            print 'Content-type: text/plain'
            print
            sys.exit(0)

    # try to see if we already have this file...
    if os.path.exists(dest_file):
        if action == 'check':
            print 'Available'
        else:
            upload_file.file.close()
            dest_file_stat = os.stat(dest_file)
            print 'Content-Type: text/plain'
            print
            print 'File %s already exists' % filename
            print 'File: %s Size: %d' % (dest_file, dest_file_stat.st_size)
        sys.exit(0)
    elif action == 'check':
        print 'Missing'
        sys.exit(0)

    # grab a temporary filename and dump our file in there
    tempfile.tempdir = module_dir
    tmpfile = tempfile.mkstemp(checksum)[1]
    tmpfd = open(tmpfile, 'w')

    # now read the whole file in
    m = getattr(hashlib, hash_type)()
    filesize = 0
    while True:
        data = upload_file.file.read(BUFFER_SIZE)
        if not data:
            break
        tmpfd.write(data)
        m.update(data)
        filesize += len(data)

    # now we're done reading, check the MD5 sum of what we got
    tmpfd.close()
    check_checksum = m.hexdigest()
    if checksum != check_checksum:
        os.unlink(tmpfile)
        send_error("%s check failed. Received %s instead of %s." %
                   (hash_type.upper(), check_checksum, checksum))

    # rename it its final name
    os.rename(tmpfile, dest_file)
    os.chmod(dest_file, 0644)

    print >> sys.stderr, '[username=%s] Stored %s (%d bytes)' % (username, dest_file, filesize)
    print 'Content-Type: text/plain'
    print
    print 'File %s size %d CHECKSUM %s stored OK' % (filename, filesize, checksum)
    if conf.getboolean('mail', 'send_mail'):
        send_email(name, checksum, filename, username, branch=branch)


if __name__ == '__main__':
    main()
