## gitlab-isolated-branch-test-deployer
## WIP - Largely untested, but placed in git as to not loose the code :)
## This README will be updated to explain usage a bit better soon

Clones and maintains directories with the latest contents of a branch.

Added by ProxiBlue:

1. Ability to fork as process
2. Read from set config files, rather than command line
3. Database import code to setup an isolated db for the branch

Tested and verified to work with Python 2.7.

### Usage

```$ ./gitlab-webhook.py start|stop|restart [config file to use]```

This will run the process and listen on the configured port for POST requests from Gitlab that correspond to the repository.
When it receives a request, it will clone the branches that were indicated as having been updated to the directory configured in the config file
A database will be imported (as a forked process) using the source db dumpfile indicated from the config file.
After import is done, an email will be sent to the branch owner email that the import is done
A symlink will be created to the branch for the site media to a common media folder as per settings in config
Use a defined source local.xml config file to set the database connection details. This will be copied to be local.xml in the app/etc folder of the new branch
In the source local.xml config use ```<dbname><![CDATA[{{DATABASENAME}}]]></dbname>``` for the dbname which will then be set to the created database


It will ignore any branch with a '/' in it's name. This is intentional, to allow for feature branches or similar that will not be cloned.

```NOTE```
a config file must be placed to read settings from
The config file contains mysql password, thus must be placed with permissions for root user to read file only
importer will start as root user, read config, then fork as defined user in config file. Actual daemon does not run as root.

example of config

general]
branch_dir = /var/www/testing/
port = 8000
post_script = /home/git/webhook-postscript

[mysql]
server = localhost
user = [USER THAT CAN CREATE/DROP DATABASES]
password = [THE PASSWORD]
source_db = /var/www/source_db.sql

[magento]
common_media = /var/www/common_media
config_xml = local.xml.testing

[service]
run_as_user = www-data
run_as_group = www-data
deamonize = true
pidfile = /tmp/branch_server.pid

[email]
smtp=[SMTP SERVER FOR EMAIL SENDING]
from=[USER TO SEND EMAIL AS]

[logging]
level = DEBUG
file = /var/log/gitlab_branch_server.log


### Acknowledgements

Inspired by gitlab-webhook-branch-deployer' by vinodc (https://github.com/vinodc/gitlab-webhook-branch-deployer)

### License

GPLv2
