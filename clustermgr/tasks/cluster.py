import re
import os

from flask import current_app as app

from clustermgr.models import LDAPServer, AppConfiguration
from clustermgr.extensions import celery, wlogger, db
from clustermgr.core.remote import RemoteClient
from clustermgr.core.olc import CnManager


def run_command(tid, c, command, container=None):
    """Shorthand for RemoteClient.run(). This function automatically logs
    the commands output at appropriate levels to the WebLogger to be shared
    in the web frontend.

    Args:
        tid (string): task id of the task to store the log
        c (:object:`clustermgr.core.remote.RemoteClient`): client to be used
            for the SSH communication
        command (string): the command to be run on the remote server
        container (string, optional): location where the Gluu Server container
            is installed. For standalone LDAP servers this is not necessary.

    Returns:
        the output of the command or the err thrown by the command as a string
    """
    if container:
        command = 'chroot {0} /bin/bash -c "{1}"'.format(container,
                                                         command)

    wlogger.log(tid, command, "debug")
    cin, cout, cerr = c.run(command)
    output = ''
    if cout:
        if 'failed' in cout:
            wlogger.log(tid, cout, 'error')
        else:
            wlogger.log(tid, cout, "debug")
        output = cout
    if cerr:
        # For some reason slaptest decides to send success message as err, so
        if 'config file testing succeeded' in cerr:
            wlogger.log(tid, cerr, "success")
        elif '-d 1' in command:  # when run with a debug flag, log it as debug
            wlogger.log(tid, cerr, "debug")
        else:
            wlogger.log(tid, cerr, "error")
        output += "\n" + cerr
    return output


def upload_file(tid, c, local, remote):
    """Shorthand for RemoteClient.upload(). This function automatically handles
    the logging of events to the WebLogger

    Args:
        tid (string): id of the task running the command
        c (:object:`clustermgr.core.remote.RemoteClient`): client to be used
            for the SSH communication
        local (string): local location of the file to upload
        remote (string): location of the file in remote server
    """
    out = c.upload(local, remote)
    wlogger.log(tid, out, 'error' if 'Error' in out else 'success')


def download_file(tid, c, remote, local):
    """Shorthand for RemoteClient.download(). This function automatically handles
    the logging of events to the WebLogger

    Args:
        tid (string): id of the task running the command
        c (:object:`clustermgr.core.remote.RemoteClient`): client to be used
            for the SSH communication
        remote (string): location of the file in remote server
        local (string): local location of the file to upload
    """
    out = c.download(remote, local)
    wlogger.log(tid, out, 'error' if 'Error' in out else 'success')


def get_syncrepl_string(server, appconf):
    """Function that creates a syncrepl config using the values from server
    and app config objects.

    Args:
        server (:obj:`LDAPServer`): an object of the LDAPServer model
        appconf (:obj:`AppConfiguration`): an object of the app config

    Returns:
        string containing the syncrepl config
    """
    f = open(os.path.join(app.root_path, 'templates', 'slapd',
                          'syncrepl.conf'))
    syncreplTemplate = f.read()
    f.close()

    vals = {'r_id': server.id, 'phost': server.ip, 'pport': server.port,
            'replication_dn': appconf.replication_dn,
            'replication_pw': appconf.replication_pw,
            'pprotocol': server.protocol,
            }
    if server.protocol == 'ldaps':
        vals['pcert'] = 'tls_cacert="/opt/symas/ssl/{0}.crt"'.format(
            server.hostname)
    else:
        vals['pcert'] = ''

    return syncreplTemplate.format(**vals).strip()


@celery.task(bind=True)
def setup_server(self, server_id, conffile):
    server = LDAPServer.query.get(server_id)
    tid = self.request.id
    if server.gluu_server:
        chdir = '/opt/gluu-server-'+server.gluu_version
    else:
        chdir = None

    wlogger.log(tid, "Connecting to the server %s" % server.hostname)
    c = RemoteClient(server.hostname)
    try:
        c.startup()
    except Exception as e:
        wlogger.log(tid, "Cannot establish SSH connection {0}".format(e),
                    "error")

    wlogger.log(tid, "Retrying with the IP address")
    c = RemoteClient(server.ip)
    try:
        c.startup()
    except Exception as e:
        wlogger.log(tid, "Cannot establish SSH connection {0}".format(e),
                    "error")
        wlogger.log(tid, "Ending server setup process.", "error")
        return False

    # Premilinary checks for standalone servers with openldap installed
    if not server.gluu_server:
        # 1. Check OpenLDAP is installed
        if c.exists('/opt/symas/bin/slaptest'):
            wlogger.log(tid, 'Checking if OpenLDAP is installed', 'success')
        else:
            wlogger.log(tid, 'Cheking if OpenLDAP is installed', 'fail')
            wlogger.log(tid, 'Kindly install OpenLDAP on the server and '
                        ' refresh this page to try setup again.')
            return
        # 2. symas-openldap.conf file exists
        if c.exists('/opt/symas/etc/openldap/symas-openldap.conf'):
            wlogger.log(tid, 'Checking symas-openldap.conf exists', 'success')
        else:
            wlogger.log(tid, 'Checking if symas-openldap.conf exists', 'fail')
            wlogger.log(tid, 'Configure OpenLDAP with /opt/gluu/etc/openldap'
                        '/symas-openldap.conf', 'warning')
            return

        # 3. Certificates
        if server.tls_cacert:
            if c.exists(server.tls_cacert):
                wlogger.log(tid, 'Checking TLS CA Certificate', 'success')
            else:
                wlogger.log(tid, 'Checking TLS CA Certificate', 'fail')
        if server.tls_servercert:
            if c.exists(server.tls_servercert):
                wlogger.log(tid, 'Checking TLS Server Certificate', 'success')
            else:
                wlogger.log(tid, 'Checking TLS Server Certificate', 'fail')
        if server.tls_serverkey:
            if c.exists(server.tls_serverkey):
                wlogger.log(tid, 'Checking TLS Server Key', 'success')
            else:
                wlogger.log(tid, 'Checking TLS Server Key', 'fail')

    # 4. Check for existance of all the directories, create them if they don't
    wlogger.log(tid, "Checking existing data and schema folders for LDAP")
    conf = open(conffile, 'r')
    for line in conf:
        if re.match('^directory', line):
            folder = line.split()[1]
            if server.gluu_server:
                folder = os.path.join(chdir, folder)
            if not c.exists(folder):
                run_command(tid, c, 'mkdir -p '+folder, chdir)
            else:
                wlogger.log(tid, folder, 'success')

    # 5. Gluu Schema file will be present - Only for Standalone
    if not server.gluu_server:
        wlogger.log(tid, "Copying Gluu Schema files to the server")
        if not c.exists('/opt/gluu/schema/openldap'):
            run_command(tid, c, 'mkdir -p /opt/gluu/schema/openldap')
        gluu_schemas = os.listdir(os.path.join(app.static_folder, 'schema'))
        for schema in gluu_schemas:
            upload_file(tid, c,
                        os.path.join(app.static_folder, 'schema', schema),
                        "/opt/gluu/schema/openldap/"+schema)

    # 6. Copy User's custom schema files if any
    schemas = os.listdir(app.config['SCHEMA_DIR'])
    if len(schemas):
        wlogger.log(tid, "Copying custom schema files to the server")
        for schema in schemas:
            local = os.path.join(app.config['SCHEMA_DIR'], schema)
            remote = "/opt/gluu/schema/openldap/"+schema
            if chdir:
                remote = chdir+"/opt/gluu/schema/openldap/"+schema
            upload_file(tid, c, local, remote)

    # 7. Copy the slapd.conf
    wlogger.log(tid, "Copying slapd.conf file to the server")
    remote = "/opt/symas/etc/openldap/slapd.conf"
    if chdir:
        remote = chdir + "/opt/symas/etc/openldap/slapd.conf"
    upload_file(tid, c, conffile, remote)

    wlogger.log(tid, "Restarting LDAP server to validate slapd.conf")
    # IMPORTANT:
    # Restart allows the server to create the mdb files for accesslog so
    # slaptest doesn't throw errors during OLC generation
    run_command(tid, c, 'service solserver restart', chdir)

    # 8. Download openldap.crt to be used in other servers for ldaps
    if server.gluu_server or server.protocol == 'ldaps':
        wlogger.log(tid, "Downloading SSL Certificate to use in other servers")
        if server.gluu_server:
            remote = chdir + '/etc/certs/openldap.crt'
        else:
            remote = server.tls_servercert
        local = os.path.join(app.config["CERTS_DIR"],
                             "{0}.crt".format(server.hostname))
        download_file(tid, c, remote, local)

    # 9. Generate OLC slapd.d
    wlogger.log(tid, "Convert slapd.conf to slapd.d OLC")
    run_command(tid, c, 'service solserver stop', chdir)
    run_command(tid, c, "rm -rf /opt/symas/etc/openldap/slapd.d", chdir)
    run_command(tid, c, "mkdir /opt/symas/etc/openldap/slapd.d", chdir)
    run_command(tid, c, "/opt/symas/bin/slaptest -f /opt/symas/etc/openldap/"
                "slapd.conf -F /opt/symas/etc/openldap/slapd.d", chdir)

    # 10. Reset ownerships
    if server.gluu_server:
        run_command(tid, c, "chown -R ldap:ldap /opt/gluu/data", chdir)
        run_command(tid, c, "chown -R ldap:ldap /opt/gluu/schema/openldap",
                    chdir)
        run_command(tid, c,
                    "chown -R ldap:ldap /opt/symas/etc/openldap/slapd.d",
                    chdir)

    # 11. Restart the solserver with the new OLC configuration
    wlogger.log(tid, "Restarting LDAP server with OLC configuration")
    log = run_command(tid, c, "service solserver start", chdir)
    if 'failed' in log:
        wlogger.log(tid, "There seems to be some issue in starting the server."
                    "Running LDAP server in debug mode for troubleshooting")
        run_command(tid, c, "service solserver start -d 1", chdir)

    # 12. Upload the Syncrepl config to all the servers
    appconf = AppConfiguration.query.first()
    cnuser = 'cn=admin,cn=config'
    providers = LDAPServer.query.filter_by(role='provider').all()
    olcSyncrepl = get_syncrepl_string(server, appconf)
    reverseSyncrepl = []

    wlogger.log(tid, "Configuring all the providers to sync with {0}".format(
        server.hostname))
    for p in providers:
        if p.id == server.id:
            continue
        # a. Copy the server certificate to the provider
        local = os.path.join(app.config["CERTS_DIR"],
                             "{0}.crt".format(server.name))
        remote = '/opt/symas/ssl/{0}.crt'.format(server.name)
        upload_file(tid, c, local, remote)

        # b. Put the syncrepl config in place
        cnm = CnManager(p.ip, p.port, True, cnuser, p.admin_pw)
        if cnm.add_olcsyncrepl(olcSyncrepl):
            wlogger.log(tid, 'Syncrepl config added to {0}'.format(p.name),
                        "success")
        else:
            # TODO Track these failures and write repair routines to fix them
            wlogger.log(tid, 'Syncrepl config adding failed for {0}'.format(
                        p.name), "fail")
            wlogger.log(tid, cnm.recent_result, "debug")

        if len(providers) == 2:  # the second server is added just now
            cnm.enable_mirrormode()
        cnm.close()

        # Generate the syncrepl for the current server from the provider
        conf = get_syncrepl_string(p, appconf)
        reverseSyncrepl.append(conf)

    # 13. Configure the current server with syncrepl of other providers
    wlogger.log(tid, "Configuring {0} to sync with all providers".format(
        server.hostname))
    for p in providers:
        if p.id == server.id:
            continue
        local = os.path.join(app.config["CERTS_DIR"],
                             "{0}.crt".format(p.name))
        remote = '/opt/symas/ssl/{0}.crt'.format(p.name)
        upload_file(tid, c, local, remote)

    if len(reverseSyncrepl) > 0:
        cnm_provider = CnManager(server.hostname, server.port, True, cnuser,
                                 server.admin_pw)
        cnm_provider.add_olcsyncrepl(reverseSyncrepl)
        cnm_provider.enable_mirrormode()
        cnm_provider.close()

    # Everything is done. Set the flag to based on the messages
    msgs = wlogger.get_messages(tid)
    setup_success = True
    for msg in msgs:
        setup_success = setup_success and msg['level'] != 'error'
    server.setup = setup_success
    db.session.commit()
