#!/usr/bin/env python

import os
import json
import BaseHTTPServer
import shlex
import subprocess
import shutil
import logging
import pwd
import grp
import MySQLdb
import ConfigParser
from multiprocessing import Process
import smtplib
from email.mime.text import MIMEText
import sys
import time
from signal import SIGTERM

branch_dir = ''

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        logger.debug("Received POST request.")
        uid = pwd.getpwnam(config.get("service", "run_as_user")).pw_uid
        gid = grp.getgrnam(config.get("service", "run_as_group")).gr_gid
        logger.debug(("Running deploy as '%s', '%s'") % (uid, gid))
        os.setgid(gid)
        os.setuid(uid)
        self.rfile._sock.settimeout(5)

        if not self.headers.has_key('Content-Length'):
            return self.error_response()

        json_data = self.rfile.read(
            int(self.headers['Content-Length'])).decode('utf-8')

        try:
            data = json.loads(json_data)
            logger.debug("Received json from gitlab '%s'" % data)
        except ValueError:
            logger.error("Unable to load JSON data '%s'" % json_data)
            return self.error_response()

        data_repository = data.get('repository', {}).get('url')
	logger.debug("data_repository is  '%s'" % data_repository)
	data_repository_name = data.get('repository', {}).get('name')
        data_user_name = data.get('user_name',{})
        logger.debug("Username '%s'" % data_user_name)
        emailto = 'lucas.vanstaden@enjo.com.au' #data_author[0].get('author', {}).get('email')

        branch_to_update = data.get('ref', '').split('refs/heads/')[-1]
        branch_to_update = branch_to_update.replace('; ', '')

        if branch_to_update == '':
            logger.error("Unable to identify branch to update: '%s'" %
                         data.get('ref', ''))
            return self.error_response()
        elif (branch_to_update in ['.', '..']):
            # Avoid malicious branches and similar.
            logger.debug("Skipping update for branch '%s'." %
                         branch_to_update)
        else:
            self.ok_response()
            branch_deletion = data['after'].replace('0', '') == ''
            branch_addition = data['before'].replace('0', '') == ''
            if branch_addition:
                self.add_branch(branch_to_update, data_repository, emailto, data_repository_name)
            elif branch_deletion:
                self.remove_branch(branch_to_update, data_repository_name)
            else:
	        self.update_branch(branch_to_update, data_repository, emailto, data_repository_name)

	    self.post_install(branch_to_update)

        logger.debug("Finished processing POST request.")

    def add_branch(self, branch, repository, emailto, data_repository_name):
        os.chdir(branch_dir)
        branch_path = os.path.join(branch_dir, branch.replace('_', '-').lower())
        if os.path.isdir(branch_path):
            return self.update_branch(branch_path, respository, emailto, data_repository_name)
        run_command("git clone --depth 1 -o origin -b %s %s %s" %
                    (branch, repository, branch_path))
        logger.debug("Added directory '%s'" % branch_path)
        self.link_media(branch_dir, branch)
	self.create_config_xml(branch, data_repository_name)
	self.create_database(branch, emailto, data_repository_name)


    def update_branch(self, branch, repository, emailto, data_repository_name):
        logger.debug("REPOSITORY '%s'" % repository)
	branch_path = os.path.join(branch_dir, branch.replace('_', '-').lower())
        if not os.path.isdir(branch_path):
            return self.add_branch(branch, repository, emailto, data_repository_name)
        os.chdir(branch_path)
        run_command("git checkout -f %s" % branch)
        run_command("git clean -fdx")
        run_command("git fetch origin %s" % branch)
        run_command("git reset --hard FETCH_HEAD")
        logger.debug("Updated branch '%s'" % branch_path)

    def remove_branch(self, branch, data_repository_name):
        dbname = branch.replace('_', '-').lower()
	branch_path = os.path.join(branch_dir, branch.replace('_', '-').lower())
        if not os.path.isdir(branch_path):
            logger.warn("Directory to remove does not exist: %s" % branch_path)
            return
        try:
            shutil.rmtree(branch_path)
            self.drop_database(dbname, data_repository_name)
        except (OSError, IOError), e:
            logger.exception("Error removing directory '%s'" % branch_path)
        else:
            logger.debug("Removed directory '%s'" % branch_path)
	return

    def ok_response(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

	return

    def importsourcesql(self, dbname, emailto):
        dbname = dbname.replace('-', '_').lower()
        structure=config.get("mysql", "source_db")
        logger.debug("Importing database '%s'" % structure)
        if os.path.isfile(structure):
            process = subprocess.Popen(["mysql", "--user=%s" % config.get("mysql", "user"), "--password=%s" % config.get("mysql", "password"), dbname],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE)
            out, err = process.communicate(file(structure).read())
        else:
            logger.error("Could not read the source db file '%s'" % structure)
        self.send_email(dbname,'Database was imported',emailto)

    def send_email(self, dbname, message, emailto):
        msg = MIMEText(message)
        msg['Subject'] = "Branch Database '%s' import update" % dbname
        msg['From'] = config.get("email", "from")
        msg['To'] = emailto
        s = smtplib.SMTP(config.get("email", "smtp"))
        s.sendmail(config.get("email", "from"), emailto, msg.as_string())
        s.quit()

    def create_config_xml(self, branch, data_repository_name):
        dbname = data_repository_name + "_" + branch
	dbname = dbname.replace('-', '_').lower()
        config_path = os.path.join(branch_dir, branch.replace('_', '-').lower(), "app/etc/", config.get("magento", "config_xml"))
        logger.debug("config.xml path is: %s" % config_path)
        if os.path.isfile(config_path):
            fin = open(config_path)
            fout = open(os.path.join(branch_dir, branch.replace('_', '-').lower(), "app/etc/local.xml"), "wt")
            for line in fin:
		fout.write( line.replace('{{DATABASENAME}}', dbname) )
            fin.close()
            fout.close()
        else:
            logger.error("Could not read the source CONFIG XML file '%s'" % config_path)
	return

    def create_database(self, branch, emailto, data_repository_name):
	dbname = data_repository_name + "_" + branch
        dbname = dbname.replace('-', '_').lower()
	logger.debug("Creating database '%s'" % dbname)
        db_connection = MySQLdb.connect(host=config.get("mysql", "server"), user=config.get("mysql", "user"), passwd=config.get("mysql", "password"))
        cursor = db_connection.cursor()
        try:
	    cursor.execute('CREATE DATABASE IF NOT EXISTS %s;' % dbname)
	    #importing the source must be a forked process, as it takes too long
	    logger.debug('Attempting to run sub-process for importing')
	    p = Process(target=self.importsourcesql, args=(dbname,emailto,))
	    p.start()
	except Exception, e:
	    logger.debug("Creating database failed '%s'" % e)
	db_connection.close()
        return

    def drop_database(self, dbname, data_repository_name):
        dbname = data_repository_name + "_" + dbname
	dbname = dbname.replace('-', '_').lower()
        db_connection = MySQLdb.connect(host=config.get("mysql", "server"), user=config.get("mysql", "user"), passwd=config.get("mysql", "password"))
        cursor = db_connection.cursor()
        logger.debug("Dropping database '%s'" % dbname)
        cursor.execute('DROP DATABASE %s;' % dbname)
        db_connection.close()
	return

    def post_install(self, branch):
        #script = "%s/%s/postinstall" % (branch_dir, branch)
        if os.path.isfile(postscript):
            if os.access(postscript, os.X_OK):
                logger.debug("Running post-install script: %s" % postscript)
                run_command("%s %s" % (postscript, branch.replace('_', '-').lower()))
            else:
                logger.debug("Post-install script is not executable: %s" %
                             postscript)
	return

    def link_media(self,branch_dir, branch):
	run_command("rm -rf %s" % os.path.join(branch_dir, branch.replace('_', '-').lower(), "media"))
	run_command("ln -s %s %s" % (config.get("magento", "common_media"), os.path.join(branch_dir, branch.replace('_', '-').lower(), "media")))

    def error_response(self):
        self.log_error("Bad Request.")
        self.send_response(400)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

def run_command(command):
    logger.debug("Running command: %s" % command)
    process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    process.wait()
    if process.returncode != 0:
        logger.error("Command '%s' exited with return code %s: %s" %
                     (command, process.returncode, process.stdout.read()))
        return ''
    return process.stdout.read()

def main():
    global branch_dir
    global postscript
    global author_email

    branch_dir = os.path.abspath(os.path.expanduser(config.get("general", "branch_dir")))
    address = str(config.get("general", "port"))
    postscript = config.get("general", "post_script")
    logger.debug('Using post script %s' % postscript)
    if address.find(':') == -1:
	host = '0.0.0.0'
	port = int(address)
    else:
	host, port = address.split(":", 1)
	port = int(port)
    server = BaseHTTPServer.HTTPServer((host, port), RequestHandler)
    logger.debug("Starting Feature Branch HTTP Server at %s:%s." % (host, port))
    try:
	server.serve_forever()
    except KeyboardInterrupt:
	pass
    logger.debug("Stopping Feature Branch HTTP Server.")
    server.server_close()


def deamonize(stdout='/dev/null', stderr=None, stdin='/dev/null',
              pidfile=None, startmsg = 'started with pid %s' ):
    '''
        This forks the current process into a daemon.
        The stdin, stdout, and stderr arguments are file names that
        will be opened and be used to replace the standard file descriptors
        in sys.stdin, sys.stdout, and sys.stderr.
        These arguments are optional and default to /dev/null.
        Note that stderr is opened unbuffered, so
        if it shares a file with stdout then interleaved output
        may not appear in the order that you expect.
    '''
    # Do first fork.
    try:
        pid = os.fork()
        if pid > 0: sys.exit(0) # Exit first parent.
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Do second fork.
    try:
        pid = os.fork()
        if pid > 0: sys.exit(0) # Exit second parent.
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    # Open file descriptors and print start message
    if not stderr: stderr = stdout
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    pid = str(os.getpid())
    sys.stderr.write("\n%s\n" % startmsg % pid)
    sys.stderr.flush()
    if pidfile: file(pidfile,'w+').write("%s\n" % pid)
     # Redirect standard file descriptors.
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

def startstop(stdout='/dev/null', stderr=None, stdin='/dev/null',
              pidfile='pid.txt', startmsg = 'started with pid %s' ):
    if len(sys.argv) > 1:
        action = sys.argv[1]
        try:
            pf  = file(pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        if 'stop' == action or 'restart' == action:
            if not pid:
                mess = "Could not stop, pid file '%s' missing.\n"
                sys.stderr.write(mess % pidfile)
                sys.exit(1)
            try:
               while 1:
                   os.kill(pid,SIGTERM)
                   time.sleep(1)
            except OSError, err:
               err = str(err)
               if err.find("No such process") > 0:
                   os.remove(pidfile)
                   if 'stop' == action:
                       sys.exit(0)
                   action = 'start'
                   pid = None
               else:
                   print str(err)
                   sys.exit(1)
        if 'start' == action:
            if pid:
                mess = "Start aborded since pid file '%s' exists.\n"
                sys.stderr.write(mess % pidfile)
                sys.exit(1)
            deamonize(stdout,stderr,stdin,pidfile,startmsg)
            return
    print "usage: %s start|stop|restart" % sys.argv[0]
    sys.exit(2)



if __name__ == '__main__':
    global logger
    global config
    global configfile

    #args = get_arguments()
    if len(sys.argv) > 1:
	if sys.argv[2:]:
	    configfile = sys.argv[2]
	else:
	    configfile = '/etc/gitlab-webhook/default.conf'
	if os.path.isfile(configfile):
	    config = ConfigParser.ConfigParser(allow_no_value=True)
	    config.read(configfile)
	    logger = logging.getLogger('gitlab-webhook-processor')
	    if config.get("logging", "level") == 'DEBUG':
		logger.setLevel(logging.DEBUG)
	    else:
		logger.setLevel(logging.INFO)
	    logging_handler = logging.FileHandler(config.get("logging", "file"))
	    logging_handler.setFormatter(
		logging.Formatter("%(asctime)s %(levelname)s %(message)s",
				  "%B %d %H:%M:%S"))
	    logger.addHandler(logging_handler)
	    logger.debug("Reading from config file '%s'" % configfile)


	    if config.get("service", "deamonize") == 'true':
		startstop(stdout=config.get("logging", "file"),
		      pidfile=config.get("service", "pidfile"))
	    main()
	else:
	    print "Could not read the config file '%s'" % configfile
    else:
	print "usage: %s start|stop|restart [path_to_config_file]" % sys.argv[0]