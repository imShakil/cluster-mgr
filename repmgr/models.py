from .application import db

from sqlalchemy.orm import relationship, backref


class LDAPServer(db.Model):
    __tablename__ = "ldap_server"
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(150))
    port = db.Column(db.Integer)
    role = db.Column(db.String(10))
    starttls = db.Column(db.Boolean)
    server_id = db.Column(db.Integer)
    replication_id = db.Column(db.Integer)
    tls_cacert = db.Column(db.Text)
    tls_servercert = db.Column(db.Text)
    tls_serverkey = db.Column(db.Text)
    initialized = db.Column(db.Boolean)
    admin_pw = db.Column(db.String(150))
    replication_pw = db.Column(db.String(150))
    provider_id = db.Column(db.Integer, db.ForeignKey('ldap_server.id'))
    consumers = relationship("LDAPServer", backref=backref(
        'provider', remote_side=[id]))

    def __init__(self, hostname, port, admin_pw, rep_pw, role, starttls, s_id,
                 r_id, provider=None, cacert=None, servercert=None,
                 serverkey=None):
        self.hostname = hostname
        self.port = port
        self.role = role
        self.admin_pw = admin_pw
        self.replication_pw = rep_pw
        self.starttls = starttls
        self.server_id = s_id
        self.replication_id = r_id
        self.tls_cacert = cacert
        self.tls_servercert = servercert
        self.tls_serverkey = serverkey
        self.initialized = False
        self.provider_id = provider

    def __repr__(self):
        return '<Server %s:%d>' % (self.hostname, self.port)


class AppConfiguration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    replication_dn = db.Column(db.String(200))
    replication_pw = db.Column(db.String(200))
    certificate_folder = db.Column(db.String(200))

    def __init__(self, replication_dn, replication_pw, cert_folder):
        self.replication_dn = replication_dn
        self.replication_pw = replication_pw
        self.certificate_folder = cert_folder