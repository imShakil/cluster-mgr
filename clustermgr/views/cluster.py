"""A Flask blueprint with the views and the business logic dealing with
the servers managed in the cluster-manager
"""
from flask import Blueprint, render_template, url_for, flash, redirect, \
    session
from flask_login import login_required

from clustermgr.core.ldap_functions import LdapOLC
from clustermgr.models import Server, AppConfiguration
from clustermgr.tasks.cluster import setup_ldap_replication, \
    installGluuServer, removeMultiMasterDeployement, installNGINX

from ..core.license import license_reminder
from ..core.license import license_manager
from ..core.license import prompt_license

cluster = Blueprint('cluster', __name__, template_folder='templates')
cluster.before_request(prompt_license)
cluster.before_request(license_reminder)


@cluster.route('/deploy_config/<server_id>', methods=['GET', 'POST'])
@login_required
@license_manager.license_required
def deploy_config(server_id):
    """Initiates replication deployement task

    Args:
        server_id (integer): id of server to be deployed
    """

    nextpage = 'index.multi_master_replication'
    whatNext = "LDAP Replication"

    s = None

    if not server_id == 'all':
        if server_id.isalnum():
            server_id = int(server_id)
            s = Server.query.get(server_id)
            if not s:
                flash("Server id {0} is not on database".format(server_id), 'warning')
                return redirect(url_for("index.multi_master_replication"))

            #Start deployment celery task
            task = setup_ldap_replication.delay(server_id)
            head = "Setting up Replication on Server: " + s.hostname

        else:
            flash("Invalid Server id {0}".format(server_id), 'warning')
            return redirect(url_for("index.multi_master_replication"))

    else:
        #Start deployment celery task
        task = setup_ldap_replication.delay(server_id)
        head = "Setting up Replication on All Servers"



    return render_template("logger.html", heading=head, server=s,
                           task=task, nextpage=nextpage, whatNext=whatNext)


@cluster.route('/remove_deployment/<int:server_id>/')
@license_manager.license_required
@login_required
def remove_deployment(server_id):
    """Initiates removal of replication deployment and back to slapd.conf

    Args:
        server_id (integer): id of server to be undeployed
    """

    thisServer = Server.query.get(server_id)
    servers = Server.query.filter(Server.id.isnot(server_id)).filter(
        Server.mmr.is_(True)).all()

    # We should check if this server is a provider for a server in cluster, so
    # iterate all servers in cluster
    for m in servers:
        ldp = LdapOLC('ldaps://{}:1636'.format(m.hostname),
                      "cn=config", m.ldap_password)
        r = None
        try:
            r = ldp.connect()
        except Exception as e:
            flash("Connection to LDAPserver {0} at port 1636 was failed:"
                  " {1}".format(m.hostname, e), "danger")

        if r:
            # If this server is a provider to another server, refuse to remove
            # deployment and update admin
            pd = ldp.getProviders()

            if thisServer.hostname in pd:
                flash("This server is a provider for Ldap Server {0}."
                      " Please first remove this server as provider.".format(
                          thisServer.hostname), "warning")
                return redirect(url_for('index.multi_master_replication'))

    # Start deployment removal celery task
    task = removeMultiMasterDeployement.delay(server_id)
    print "TASK STARTED", task.id
    head = "Removing Deployment"
    nextpage = "index.multi_master_replication"
    whatNext = "Multi Master Replication"
    return render_template("logger.html", heading=head, server=thisServer,
                           task=task, nextpage=nextpage, whatNext=whatNext)


@cluster.route('/install_ldapserver')
@login_required
@license_manager.license_required
def install_ldap_server():
    """Initiates installation of non-gluu ldap server"""

    # Start non-gluu ldap server installation celery task
    task = InstallLdapServer.delay(session['nongluuldapinfo'])
    print "TASK STARTED", task.id
    head = "Installing Symas Open-Ldap Server on " + \
        session['nongluuldapinfo']['fqn_hostname']
    nextpage = "index.multi_master_replication"
    whatNext = "Multi Master Replication"
    return render_template("logger.html", heading=head, server="",
                           task=task, nextpage=nextpage, whatNext=whatNext)


@cluster.route('/install_gluu_server/<int:server_id>/')
@login_required
@license_manager.license_required
def install_gluu_server(server_id):
    """Initiates installation of gluu server

    Args:
        server_id (integer): id fo server to be installed
    """

    server = Server.query.get(server_id)
    appconf = AppConfiguration.query.first()

    # Start gluu server installation celery task
    task = installGluuServer.delay(server_id)

    print "Install Gluu Server TASK STARTED", task.id
    head = "Installing Gluu Server ({0}) on {1}".format(appconf.gluu_version, server.hostname)
    nextpage = "index.home"
    whatNext = "Dashboard"
    return render_template("logger.html", heading=head, server=server.hostname,
                           task=task, nextpage=nextpage, whatNext=whatNext)


@cluster.route('/installnginx/')
@login_required
@license_manager.license_required
def install_nginx():
    """Initiates installation of nginx load balancer"""
    appconf = AppConfiguration.query.first()

    # Start nginx  installation celery task
    task = installNGINX.delay(appconf.nginx_host)

    print "Install NGINX TASK STARTED", task.id
    head = "Installing NGINX Server on {0}".format(appconf.nginx_host)
    nextpage = "index.multi_master_replication"
    whatNext = "LDAP Replication"
    return render_template("logger.html", heading=head, server=appconf.nginx_host,
                           task=task, nextpage=nextpage, whatNext=whatNext)
