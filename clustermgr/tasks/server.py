# -*- coding: utf-8 -*-

import os
import re
import time
import subprocess
import uuid
import traceback
import StringIO
import json
import binascii

from flask import current_app as app
from ldap3 import SUBTREE, BASE, MODIFY_REPLACE
from clustermgr.models import Server, AppConfiguration
from clustermgr.extensions import wlogger, db, celery

from clustermgr.core.remote import RemoteClient, get_connection
from clustermgr.config import Config

from clustermgr.core.clustermgr_installer import Installer
from clustermgr.core.utils import get_setup_properties, \
    modify_etc_hosts, as_boolean, get_proplist, write_setup_properties_file, \
    parse_setup_properties

from clustermgr.core.jproperties import Properties
from clustermgr.core.ldap_functions import LdapOLC, getLdapConn


@celery.task(bind=True)
def collect_server_details(self, server_id):
    print "Start collecting server details task"
    app_conf = AppConfiguration.query.first()
    
    if server_id == -1:
        #mock server
        server = Server( hostname=app_conf.nginx_host,
                         ip = app_conf.nginx_ip
                         )
    else:
        server = Server.query.get(server_id)
        hostname = server.hostname
        ip = server.ip
    
    installer = Installer(
                server,
                app_conf.gluu_version,
                logger_task_id=-1,
                server_os=None,
                ssh_port=server.ssh_port
                )

    os_type = installer.get_os_type()

    if server_id == -1:
        app_conf.nginx_os = os_type
        db.session.commit()
        return


    # 0. Make sure it is a Gluu Server
    server.gluu_server = installer.is_gluu_installed()

    # 1. The components installed in the server
    components = {
        'oxAuth': 'opt/gluu/jetty/oxauth',
        'oxTrust': 'opt/gluu/jetty/identity',
        'Shibboleth': 'opt/shibboleth-idp',
        'oxAuthRP': 'opt/gluu/jetty/oxauth-rp',
        #'Asimba': 'opt/gluu/jetty/asimba',
        'Passport': 'opt/gluu/node/passport',
    }
    installed = []
    
    if server.gluu_server:
        for component, marker in components.iteritems():
            marker = os.path.join(installer.container, marker)
            if installer.conn.exists(marker):
                installed.append(component)

    server.components = ",".join(installed)

    server.os = os_type

    db.session.commit()


def set_up_ldap_cache_cleaner(installer, ldap_cache_clean_period):
    installer.conn.run('mkdir -p /opt/gluu-server/var/log/ldap_cache_cleaner')
    installer.conn.run('chown jetty:jetty /opt/gluu-server/var/log/ldap_cache_cleaner')
    installer.upload_file(
        os.path.join(app.root_path, 'core/ldap_cache_cleanup.py'),
        '/opt/gluu-server/opt/gluu/bin/ldap_cache_cleanup.py'
        )
    installer.conn.run('chmod +x /opt/gluu-server/opt/gluu/bin/ldap_cache_cleanup.py')
    installer.put_file('/opt/gluu-server/etc/cron.d/ldap_cache_cleanup',
    '*/{} * * * *    jetyy    /opt/gluu/bin/ldap_cache_cleanup.py\n'.format(ldap_cache_clean_period))

    if 'CentOS' in installer.server_os or 'RHEL' in installer.server_os:
        installer.restart_service('crond')
    else:
        installer.restart_service('cron')

def modify_hosts(task_id, conn, hosts, chroot='/', server_host=None, server_id=''):
    wlogger.log(task_id, "Modifying /etc/hosts of server {0}".format(server_host), server_id=server_id)
    
    hosts_file = os.path.join(chroot,'etc/hosts')
    
    result, old_hosts = conn.get_file(hosts_file)
    
    if result:
        new_hosts = modify_etc_hosts(hosts, old_hosts.read())
        conn.put_file(hosts_file, new_hosts)
        wlogger.log(task_id, "{} was modified".format(hosts_file), 'success', server_id=server_id)
    else:
        wlogger.log(task_id, "Can't receive {}".format(hosts_file), 'fail', server_id=server_id)


    if chroot:

        hosts_file = os.path.join(chroot, 'etc/hosts')
        
        result, old_hosts = conn.get_file(hosts_file)
        
        if result:
            new_hosts = modify_etc_hosts(hosts, old_hosts.read())
            conn.put_file(hosts_file, new_hosts)
            wlogger.log(task_id, "{0} of server {1} was modified".format(hosts_file, server_host), 'success', server_id=server_id)
        else:
            wlogger.log(task_id, "Can't receive {}".format(hosts_file), 'fail', server_id=server_id)


def download_and_upload_custom_schema(task_id, primary_conn, conn, ldap_type, gluu_server):
    """Downloads custom ldap schema from primary server and 
        uploads to current server represented by conn
    Args:
        tid (string): id of the task running the command,
        primary_conn (:object:`clustermgr.core.remote.RemoteClient`): client to be used
            for the SSH communication, representing primary server

        conn (:object:`clustermgr.core.remote.RemoteClient`): client to be used
            for the SSH communication, representing current server
        ldap_type (string): type of ldapserver, currently opendj
        gluu_server: Gluu server name
    """
    
    wlogger.log(task_id, 'Downloading custom schema files' 
                    'from primary server and upload to this server')
    custom_schema_files = primary_conn.listdir("/opt/{}/opt/gluu/schema/{}/".format(
                                                    gluu_server, ldap_type))

    if custom_schema_files[0]:
        
        schema_folder = '/opt/{}/opt/gluu/schema/{}'.format(
                        gluu_server, ldap_type)
        if not conn.exists(schema_folder):
            conn.run('mkdir -p {}'.format(schema_folder))
        
        for custom_schema in custom_schema_files[1]:
            schema_filename = '/opt/{0}/opt/gluu/schema/{2}/{1}'.format(
                                                gluu_server, custom_schema, ldap_type)
                                                
            result, schema = primary_conn.get_file(schema_filename)
            if result:
                conn.put_file(schema_filename, schema.read())
                wlogger.log(tid, 
                    '{0} dowloaded from from primary and uploaded'.format(
                                                            custom_schema),
                                                            'debug')

                if ldap_type == 'opendj':

                    opendj_path = ('/opt/{}/opt/opendj/config/schema/'
                                '999-clustmgr-{}').format(gluu_server, custom_schema)
                    conn.run('cp {} {}'.format(schema_filename, opendj_path))





@celery.task(bind=True)
def task_install_gluu_server(self, server_id):
    
    task_id = self.request.id

    """
    for i in range(5):
        wlogger.log(task_id, str(i))
        time.sleep(1)
        
    
    wlogger.log(task_id, "2", "setstep")
    wlogger.log(task_id, "New Step")
    
    for i in range(5):
        wlogger.log(task_id, str(i))
        time.sleep(1)

    wlogger.log(task_id, "3", "setstep")
    wlogger.log(task_id, "New Step")
    
    
    for i in range(5):
        wlogger.log(task_id, str(i))
        time.sleep(1)
    
    return
    """

    try:
        install_gluu_server(task_id, server_id)
    except:
        raise Exception(traceback.format_exc())

def checkOfflineRequirements(installer, server, appconf):
    os_type, os_version = server.os.split()

    wlogger.log(installer.logger_task_id, "Checking if dependencies were installed")

    #Check if archive type and os type matches    
    if not appconf.gluu_archive.endswith('.'+installer.clone_type):
        wlogger.log(installer.logger_task_id,
                    "Os type does not match gluu archive type", 'error')
        return False

    wlogger.log(installer.logger_task_id,
                    "Os type matches with gluu archive", 'success')
    
    #Determine gluu version
    a_path, a_fname = os.path.split(appconf.gluu_archive)
    
    version_re = r'gluu-server(-nochroot)*(_|-)(?P<gluu_version>(\d+).(\d+)((.\d+)?)(\.\d+)?)'
    
    m = re.search(version_re, a_fname)


    if m:
        gv = m.group('gluu_version')
        gv = gv.split('_')[0]
        if '-nochroot' in a_fname:
            gv = 'nochroot-' + gv
        appconf.gluu_version = gv
        db.session.commit()
        wlogger.log(
            installer.logger_task_id,
            "Gluu version was determined as {0} from gluu archive".format(gv),
            'success'
            )
        installer.gluu_version = gv
    else:
        wlogger.log(installer.logger_task_id,
                    "Gluu version could not be determined from gluu archive", 
                    'error')
        return False


    #check if curl exists on the system
    cmd = 'which curl'
    result = installer.run(cmd, inside=False, error_exception='no curl in')

    curlexist = False if not 'curl' in result[1] else True

    if result[1]:
        wlogger.log(installer.logger_task_id, "curl was installed",'success')
    else:
        wlogger.log(
            installer.logger_task_id, 
            'curl was not installed. Please install curl on the host '
            'system (outside of the container) and retry.', 
            'error'
            )
        return False
        

    #Check if python is installed
    if installer.conn.exists('/usr/bin/python'):
        wlogger.log(installer.logger_task_id, "Python was installed",'success')
    else:
        wlogger.log(
            installer.logger_task_id, 
            'python was not installed. Please install python on the host '
            'system (outside of the container) and retry.', 
            'error'
            )
        return False

    if installer.clone_type == 'rpm' and installer.os_version == '8':
        #Check if chrony was installed
        if installer.conn.exists('/usr/sbin/chronyd'):
            wlogger.log(installer.logger_task_id, "chronyd was installed", 'success')
        else:
            wlogger.log(
                installer.logger_task_id, 
                'chrony was not installed. Please install chrony on the host '
                'system (outside of the container) and retry.', 
                'error'
                )
            return False
    else:
        #Check if ntp was installed
        if installer.conn.exists('/usr/sbin/ntpdate'):
            wlogger.log(installer.logger_task_id, "ntpdate was installed", 'success')
        else:
            wlogger.log(
                installer.logger_task_id, 
                'ntpdate was not installed. Please install ntpdate on the host '
                'system (outside of the container) and retry.', 
                'error'
                )
            return False

    #Check if stunnel was installed
    if installer.conn.exists('/usr/bin/stunnel') or installer.conn.exists('/bin/stunnel'):
        wlogger.log(installer.logger_task_id, "stunnel was installed", 'success')
    else:
        wlogger.log(
            installer.logger_task_id, 
            'stunnel was not installed. Please install stunnel on the host '
            'system (outside of the container) and retry.', 
            'error'
            )
        return False

    return True


def make_opendj_listen_world(server, installer):

    opendj_commands = [
            "sed -i 's/dsreplication.java-args=-Xms8m -client/dsreplication.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true/g' /opt/opendj/config/java.properties",
            "/opt/opendj/bin/dsconfig -h localhost -p 4444 -D 'cn=directory manager' -w $'{}' -n set-administration-connector-prop  --set listen-address:0.0.0.0 -X".format(server.ldap_password),
            "/opt/opendj/bin/dsconfig -h localhost -p 4444 -D 'cn=directory manager' -w $'{}' -n set-connection-handler-prop --handler-name 'LDAPS Connection Handler' --set enabled:true --set listen-address:0.0.0.0 -X".format(server.ldap_password),
            ]

    opendj_commands.append('systemctl stop opendj')
    opendj_commands.append('systemctl start opendj')

    for command in opendj_commands:
        installer.run(command)

    #wait a couple of seconds for starting opendj
    time.sleep(5)

def install_gluu_server(task_id, server_id):

    server = Server.query.get(server_id)
    primary_server = Server.query.filter_by(primary_server=True).first()

    app_conf = AppConfiguration.query.first()

    enable_command = None
    gluu_server = 'gluu-server'

    # local setup properties file path
    setup_properties_file = os.path.join(
                                        Config.DATA_DIR, 
                                        'setup.properties'
                                        )


    # get setup properties
    setup_prop = get_setup_properties()
    wlogger.log(task_id, app_conf.gluu_version)

    # If os type of this server was not idientified, return to home
    if not server.os:
        wlogger.log(task_id, "OS type has not been identified.", 'fail')
        return False

    if server.os != primary_server.os:
        wlogger.log(task_id, "OS type is not the same as primary server.", 'fail')
        return False

    # If this is not primary server, we will download setup.properties
    # file from primary server
    if not server.primary_server:
        wlogger.log(task_id, "Check if Primary Server is Installed", 'head')

        primary_server_installer = Installer(
                                primary_server,
                                app_conf.gluu_version,
                                logger_task_id=task_id,
                                server_os=server.os,
                                ssh_port=primary_server.ssh_port
                            )

        if not primary_server_installer.conn:
            wlogger.log(task_id, "Primary server is reachable via ssh.", "fail"
                        )
            return False
        else:
            if not primary_server_installer.is_gluu_installed():
                wlogger.log(task_id, "Primary server is not installed.","fail")
                return False

            else:
                wlogger.log(task_id, "Primary server is installed.", "success")

    wlogger.log(task_id, "Preparing Server for installation", 'head')
    installer = Installer(
                    server, 
                    app_conf.gluu_version, 
                    logger_task_id=task_id, 
                    server_os=server.os,
                    ssh_port=server.ssh_port
                    )

    if not installer.conn:
        return False

    if app_conf.offline:
        if not checkOfflineRequirements(installer, server, app_conf):
            return False

    if not app_conf.offline:
        
        #check if curl exists on the system
        cmd = 'which curl'
        result = installer.run(cmd, inside=False)
        if not result[1]:
            installer.install('curl', inside=False)
        
        
        #nc is required for dyr run
        netcat_package = 'nc'
        if installer.clone_type == 'deb':
            netcat_package = 'netcat'
        installer.install(netcat_package, inside=False)
            
        if not installer.conn.exists('/usr/bin/python'):
            installer.install('python', inside=False)



        #add gluu server repo and imports signatures
        if ('Ubuntu' in server.os) or ('Debian' in server.os):

            if server.os == 'Ubuntu 18':
                dist = 'bionic'
            elif server.os == 'Ubuntu 20':
                dist = 'focal'

            if 'Ubuntu' in server.os:
                cmd_list = (
                'curl https://repo.gluu.org/ubuntu/gluu-apt.key | '
                'apt-key add -',
                'echo "deb https://repo.gluu.org/ubuntu/ {0} main" '
                '> /etc/apt/sources.list.d/gluu-repo.list'.format(dist)
                )

            elif 'Debian' in server.os:
                cmd_list = (
                'curl https://repo.gluu.org/debian/gluu-apt.key | '
                'apt-key add -',
                'echo "deb https://repo.gluu.org/debian/ stable main" '
               '> /etc/apt/sources.list.d/gluu-repo.list'
                )


            for cmd in cmd_list:
                installer.run(cmd, inside=False, error_exception='Xferd')

            cmd = 'DEBIAN_FRONTEND=noninteractive apt-get update'
            cin, cout, cerr = installer.run(cmd, inside=False)

            if 'dpkg --configure -a' in cerr:
                cmd = 'dpkg --configure -a'
                wlogger.log(task_id, cmd, 'debug')
                installer.run(cmd, inside=False)

        elif 'CentOS' in server.os or 'RHEL' in server.os:
            installer.install('ca-certificates', inside=False, error_exception='__ALL__')
            if not installer.conn.exists('/usr/bin/wget'):
                installer.install('wget', inside=False, error_exception='warning: /var/cache/')

            os_name, os_version = server.os.split()
            enable_command  = '/sbin/gluu-serverd enable'

            cmd = (
                  'wget https://repo.gluu.org/{0}/Gluu-{0}{1}.repo -O '
                  '/etc/yum.repos.d/Gluu.repo'
                  ).format(os_name.lower(), os_version)

            installer.run(cmd, inside=False, error_exception='__ALL__')

            cmd = (
              'wget https://repo.gluu.org/{}/RPM-GPG-KEY-GLUU -O '
              '/etc/pki/rpm-gpg/RPM-GPG-KEY-GLUU'
              ).format(os_name.lower())

            installer.run(cmd, inside=False, error_exception='__ALL__')

            cmd = 'rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-GLUU'
            installer.run(cmd, inside=False, error_exception='__ALL__')

            cmd = 'yum clean all'
            installer.run(cmd, inside=False, error_exception='__ALL__')


    wlogger.log(task_id, "Check if Gluu Server was installed", 'action')

    gluu_installed = False

    #Determine if a version of gluu server was installed.

    if installer.conn.exists('/opt/gluu-server'):
        if installer.gluu_version.startswith('nochroot'):
            wlogger.log(installer.logger_task_id,
                    "Can't re-install host installed gluu server", 'error')
            return False

        gluu_version = installer.get_gluu_version(installed=True)
        gluu_installed = True

        stop_result = installer.stop_gluu()

        #If gluu server is installed, first stop it then remove
        if "Can't stop gluu server" in stop_result:
            cmd = 'rm -f /var/run/{0}.pid'.format(gluu_server)
            installer.run(cmd, inside=False,
                        error_exception='__ALL__')

            cmd = (
              "df -aP | grep %s | awk '{print $6}' | xargs -I "
              "{} umount -l {}" % (gluu_server)
              )
            installer.run(cmd, 
                            inside=False, 
                            error_exception='__ALL__')
            
            stop_result = installer.stop_gluu()

        installer.remove('gluu-server', inside=False)


    if not gluu_installed:
        wlogger.log(
                    task_id, 
                    "Gluu Server was not previously installed", 
                    "debug"
                    )

    wlogger.log(task_id, "2", "setstep")
    #JavaScript on logger duplicates next log if we don't add this
    time.sleep(1)


    wlogger.log(task_id, "Installing Gluu Server: " + gluu_server)


    if app_conf.offline:

        gluu_archive_fn = os.path.split(app_conf.gluu_archive)[1]
        wlogger.log(task_id, "Uploading {}".format(gluu_archive_fn))

        installer.upload_file(app_conf.gluu_archive, os.path.join('/root', gluu_archive_fn))

        if installer.clone_type == 'deb':
            install_command = 'dpkg -i /root/{}'.format(gluu_archive_fn)
        else:
            install_command = 'rpm -i /root/{}'.format(gluu_archive_fn)

        installer.run(install_command, inside=False, error_exception='__ALL__')

    else:

        if server.os in ('Ubuntu 18', 'Ubuntu 20'):
            installer.put_file('/etc/apt/apt.conf.d/90forceconf', 'Dpkg::Options {\n  "--force-confdef";\n  "--force-confold";\n}')
            if app_conf.gluu_version < 4.2.1:
                print(type(app_conf.gluu_version), app_conf.gluu_version)
                ubuntu_version_name = 'bionic' if server.os in ('Ubuntu 18') else 'focal'
                gluu_package_name = gluu_server + '=' + app_conf.gluu_version + '~' + ubuntu_version_name
            else:
                gluu_package_name = gluu_server + '=' + app_conf.gluu_version + '~ubuntu' + installer.os_version + '.04'
        else:
            gluu_package_name = gluu_server + '-' + app_conf.gluu_version

        cmd = installer.get_install_cmd(gluu_package_name, inside=False)

        ubuntu_re = re.compile('\[(\s|\w|%|/|-|\.)*\]')
        ubuntu_re_2 = re.compile('\(Reading database ... \d*')
        centos_re = re.compile(' \[(=|-|#|\s)*\] ')

        re_list = [ubuntu_re, ubuntu_re_2, centos_re]

        all_cout = installer.run_channel_command(cmd, re_list)

        #If previous installation was broken, make a re-installation. 
        #This sometimes occur on ubuntu installations
        if 'half-installed' in all_cout:
            if ('Ubuntu' in server.os) or ('Debian' in server.os):
                cmd = 'DEBIAN_FRONTEND=noninteractive  apt-get install --reinstall -y '+ gluu_server
                installer.run_channel_command(cmd, re_list)

    if enable_command:
        installer.run(enable_command, inside=False, error_exception='__ALL__')

    installer.start_gluu()

    
    #Since we will make ssh inot centos container, we need to wait ssh server to
    #be started properly
    wlogger.log(task_id, "Sleeping 10 secs to wait for gluu server start properly.")
    time.sleep(10)

    if installer.clone_type == 'rpm' and installer.os_version < '8':
        installer.run('cp -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem {}'.format(os.path.join(installer.container, 'etc/pki/ca-trust/extracted/pem/')), inside=False)
        installer.run('cp -f /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt {}'.format(os.path.join(installer.container, 'etc/pki/ca-trust/extracted/openssl/')), inside=False)

    if installer.gluu_version.startswith('nochroot'):
        installer.run('ln -s / /opt/gluu-server', inside=False)

    # If this server is primary, upload local setup.properties to server
    if server.primary_server:
        wlogger.log(task_id, "Uploading setup.properties")
        result = installer.upload_file(setup_properties_file, 
                 '/opt/gluu-server/root/setup.properties')

    # If this server is not primary, get setup.properties.last from primary
    # server and upload to this server
    else:
        #this is not primary server, so download setup.properties.last
        #from primary server and upload to this server

        # ldap_paswwrod of this server should be the same with primary server
        ldap_passwd = None

        remote_file = '/opt/gluu-server/install/community-edition-setup/setup.properties.last'
        wlogger.log(task_id, 'Downloading setup.properties.last from primary server', 'debug')

        prop_list = get_proplist()
        prop_io = None

        #get setup.properties.last from primary server.
        if primary_server_installer.conn.exists(remote_file):
            result = primary_server_installer.conn.get_file(remote_file)
            prop_io = result[1]
        else:
            remote_file += '.cm'
            cmd_unenc = "openssl enc -d -aes-256-cbc -in /install/community-edition-setup/setup.properties.last.enc -k $'{}' -out /install/community-edition-setup/setup.properties.last.cm".format(server.ldap_password)
            cmd_fn = os.path.join(installer.container, 'root/.cmd')
            primary_server_installer.put_file(cmd_fn, cmd_unenc)
            wlogger.log(task_id, "Executing: " + cmd_unenc, 'debug')
            primary_server_installer.run('bash /root/.cmd')
            primary_server_installer.run('rm -f /root/.cmd')
            result = primary_server_installer.conn.get_file(remote_file)
            prop_io = result[1]
            installer.run('rm -f ' + remote_file)

        prop = Properties()
        
        if prop_io:
            tmp_prop_file = '/tmp/{}.properties'.format(binascii.b2a_hex(os.urandom(4)))
            with open(tmp_prop_file, 'wb') as w:
                w.write(prop_io.read())
            prop = parse_setup_properties(tmp_prop_file)
            prop_keys = prop.keys()
            for p in prop_keys[:]:
                if not p in prop_list:
                    print ("deleting " + p)
                    del prop[p]

            prop['ip'] = str(server.ip)
            prop['ldap_type'] = 'opendj'
            prop['hostname'] = str(app_conf.nginx_host)
            #prop['ldap_hostname'] = server.hostname
            ldap_passwd = prop['ldapPass']

            write_setup_properties_file(prop, tmp_prop_file)

            #put setup.properties to server
            remote_file_new = '/opt/gluu-server/root/setup.properties'
            installer.upload_file(tmp_prop_file, remote_file_new)

            os.remove(tmp_prop_file)

            if ldap_passwd:
                server.ldap_password = ldap_passwd
        else:
            wlogger.log(task_id, 
                    "Can't download setup.properties.last from primary server",
                    'fail')
            wlogger.log(task_id, 
                        "Ending server installation process.",
                        "error")
            return

    wlogger.log(task_id, "3", "setstep")
    #JavaScript on logger duplicates next log if we don't add this
    time.sleep(1)

    setup_py = os.path.join(app.root_path,'setup', 'setup_{}.py'.format(app_conf.gluu_version.replace('nochroot-', '')))
    if os.path.exists(setup_py):
        remote_py = '/opt/gluu-server/install/community-edition-setup/setup.py'
        installer.upload_file(setup_py, remote_py)
        installer.run('chmod +x ' + remote_py, inside=False)

    opendj_properties_fn = os.path.join(app.root_path, 'templates', 'opendj', 'opendj-setup.properties')

    if os.path.exists(opendj_properties_fn):
        remote_fn = '/opt/gluu-server/install/community-edition-setup/templates/opendj-setup.properties'
        installer.upload_file(opendj_properties_fn, remote_fn)

    setup_cmd = '/install/community-edition-setup/setup.py -f /root/setup.properties --listen_all_interfaces -n'
    if app_conf.gluu_version.replace('nochroot-', '') >= '4.2.0':
        setup_cmd += ' -c'

    #Don't load base data for secondary nodes
    if not server.primary_server:
        setup_cmd += ' --no-data'

    cmd = installer.run_command.format(setup_cmd)
    
    re_list = [re.compile(' \[(#|\s)*\] ')]
    
    all_cout = installer.run_channel_command(cmd, re_list)

    wlogger.log(task_id, "4", "setstep")
    #JavaScript on logger duplicates next log if we don't add this
    time.sleep(1)

    if app_conf.modify_hosts:
        all_server = Server.get_all()
        host_ip = [ (ship.hostname, ship.ip) for ship in all_server ]
        modify_hosts(task_id, installer.conn, host_ip, '/opt/gluu-server/', server.hostname)


    ldapc = LdapOLC(
                    'ldaps://{}:1636'.format(server.hostname),
                    'cn=Directory Manager',
                    server.ldap_password
                     )

    wlogger.log(task_id, "Connecting LDAP Server: {}".format(server.hostname), 'debug')


    if installer.clone_type == 'rpm' and installer.os_version == '8' and not installer.conn.exists(os.path.join(installer.container, 'usr/sbin/crond')):
        installer.install('crontabs')
        installer.enable_service('crond')
        installer.start_service('crond')
    
    if server.primary_server:
        ldapc.connect()
        ldapc.set_ldap_cache_cleanup_interval()
        set_up_ldap_cache_cleaner(installer, app_conf.ldap_cache_clean_period)

    # Get slapd.conf from primary server and upload this server
    if not server.primary_server:

        #we need to download certificates
        #from primary server and upload to this server, then will delete and
        #import keys
        wlogger.log(task_id, "Downloading certificates from primary "
                         "server and uploading to this server")
        certs_remote_tmp = "/tmp/certs_"+str(uuid.uuid4())[:4].upper()+".tgz"
        certs_local_tmp = "/tmp/certs_"+str(uuid.uuid4())[:4].upper()+".tgz"

        cmd = [
                'tar -zcf {} /opt/{}/etc/certs/'.format(certs_remote_tmp, gluu_server),
                '/opt/{}/install/community-edition-setup/output/scim-rp.jks'.format(gluu_server),
                ]

        passport_config = '/opt/{}/etc/gluu/conf/passport-config.json'.format(gluu_server)
        if primary_server_installer.conn.exists(passport_config):
            cmd.append(passport_config)

        primary_server_installer.run(' '.join(cmd), inside=False, error_exception='Removing leading')

        primary_server_installer.download_file(certs_remote_tmp, certs_local_tmp)
       
        installer.upload_file(certs_local_tmp, 
                            "/tmp/certs.tgz".format(gluu_server))

        cmd = 'tar -zxf /tmp/certs.tgz -C /'
        installer.run(cmd, inside=False)

        #delete old keys and import new ones
        wlogger.log(task_id, 'Manuplating keys')
        for suffix in (
                'httpd',
                'shibIDP',
                'idp-encryption',
                #'asimba',
                setup_prop['ldap_type'],
                ):
            installer.delete_key(suffix, app_conf.nginx_host)
            installer.import_key(suffix, app_conf.nginx_host)

        download_and_upload_custom_schema(  
                                            task_id,
                                            primary_server_installer.conn,
                                            installer.conn, 
                                            'opendj', gluu_server
                                        )
                                        
        #create base dn for o=metric backend    
        wlogger.log(task_id, "Creating base dn for o=metric backend")
        
        if not ldapc.connect():
            wlogger.log(task_id, "Cannot connect to ldap server. Failed to "
                            "create base dn for o=metric backend", 'warning')
        else:
            r = ldapc.checkBaseDN(dn='o=metric', 
                                attributes={
                                    'objectClass': ['top', 'organization'],
                                    'o': 'site'
                                        }
                                )
            if r:
                wlogger.log(task_id, "o=metric created", 'success')
                            
            r = ldapc.checkBaseDN(dn='ou=statistic,o=metric', 
                                attributes={
                                  'objectClass': ['top', 'organizationalUnit'],
                                  'ou': 'statistic'
                                      }
                                )
            if r:
                wlogger.log(task_id, "ou=statistic,o=metric created", 'success')


        if as_boolean(setup_prop['installCasa']):
            #we need to copy casa.json and oxd_db.mv.db from primry server
            casa_files = [
                        os.path.join(installer.container, 'opt/oxd-server/data/oxd_db.mv.db')
                        ]

            if installer.gluu_version.replace('nochroot-', '') < '4.2.0':
                casa_files.append(os.path.join(installer.container, 'etc/gluu/conf/casa.json'))

            tmp_dir = os.path.join('/tmp', str(uuid.uuid4())[:8])
            os.mkdir(tmp_dir)
            for remote_fp in casa_files:
                local_fp = os.path.join(tmp_dir, os.path.basename(remote_fp))
                primary_server_installer.download_file(remote_fp, local_fp)
                installer.upload_file(local_fp, remote_fp)
                installer.run('chown jetty:jetty ' + remote_fp)

        wlogger.log(task_id, "Gluu Server successfully installed")

    else:
        #this is primary server so we need to upload local custom schemas if any
        custom_schema_dir = os.path.join(Config.DATA_DIR, 'schema')
        custom_schemas = os.listdir(custom_schema_dir)

        if custom_schemas:
            schema_folder = '/opt/gluu/schema/{}'.format(ldap_type)
            if not installer.conn.exists(schema_folder):
                installer.conn.run('mkdir -p {}'.format(schema_folder))

            for schema_file in custom_schemas:
                
                local = os.path.join(custom_schema_dir, schema_file)
                remote = '/opt/{0}/opt/gluu/schema/{2}/{1}'.format(
                    gluu_server, schema_file, ldap_type)
                result = installer.upload_file(local, remote)


    server.gluu_server = True
    db.session.commit()

    #ntp is required for time sync, since ldap replication will be
    #done by time stamp. If not isntalled, install and configure crontab
    wlogger.log(task_id, "Checking if time sysnc server (ntp/chronyd) is installed and configured.")

    if installer.clone_type == 'rpm' and installer.os_version == '8':
        if installer.conn.exists('/usr/sbin/chronyd'):
            wlogger.log(task_id, "chrony was installed", 'success')
        else:
            installer.install('chrony', inside=False)
        
        installer.enable_service('chronyd', inside=False)
        installer.start_service('chronyd', inside=False)
        
    else:

        if installer.conn.exists('/usr/sbin/ntpdate'):
            wlogger.log(task_id, "ntp was installed", 'success')
        else:
            installer.install('ntpdate', inside=False)

        #run time sync an every minute
        installer.put_file('/etc/cron.d/setdate',
                    '* * * * *    root    /usr/sbin/ntpdate -s time.nist.gov\n')
        wlogger.log(task_id, 'Crontab entry was created to update time in every minute',
                         'debug')

    if 'CentOS' in server.os or 'RHEL' in server.os:
        installer.restart_service('crond')
    else:
        installer.restart_service('cron')

    # we need to download pathced oxauth.war for key rotation for version 4.0
    if (app_conf.gluu_version == '4.0') and (not app_conf.offline):
        cmd = ('wget -nv https://ox.gluu.org/maven/org/gluu/oxauth-server/'
                '4.0.sp1/oxauth-server-4.0.sp1.war -O '
                '/opt/gluu/jetty/oxauth/webapps/oxauth.war')
        installer.run(cmd, error_exception='__ALL__')

    # set keyRegenerationEnabled to False
    if server.primary_server:
        
        wlogger.log(task_id, 'Setting keyRegenerationEnabled to False',
                     'debug')
        
        ldp = getLdapConn(server.hostname, 'cn=directory manager', server.ldap_password)
        if ldp:

            if ldp.conn.search(
                            search_base='ou=oxauth,ou=configuration,o=gluu', 
                            search_scope=BASE,
                            search_filter='(objectclass=*)',
                            attributes=["oxAuthConfDynamic"]):

                search_result = ldp.conn.response

                oxAuthConfDynamic_s = search_result[0]["attributes"]["oxAuthConfDynamic"][0]
                oxAuthConfDynamic = json.loads(oxAuthConfDynamic_s)
                oxAuthConfDynamic['keyRegenerationEnabled'] = False
                oxAuthConfDynamic_s = json.dumps(oxAuthConfDynamic, indent=2)

                r = ldp.conn.modify(
                            search_result[0]['dn'], 
                            {"oxAuthConfDynamic": [MODIFY_REPLACE, oxAuthConfDynamic_s]}
                            )
        else:
            wlogger.log(task_id, 
                        "LDAP Connection failed.",
                        "error")
            return
    else:
        installer.restart_service('opendj')
        
    wlogger.log(task_id, "5", "setstep")
    return True


@celery.task(bind=True)
def task_test(self):
    
    task_id = self.request.id

    for si in range(1,4):
        for i in range(3):
            wlogger.log(task_id, str(i), server_id=si)
            time.sleep(1)

    wlogger.log(task_id, "2", "setstep")
    
    for si in range(1,4):
        for i in range(3):
            wlogger.log(task_id, str(i), server_id=si)
            time.sleep(1)
