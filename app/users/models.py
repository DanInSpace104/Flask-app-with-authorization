# coding: utf-8

from app import config, db, login
from flask_login import UserMixin
from itsdangerous import BadSignature, SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from passlib.apps import custom_app_context as pwd_context

roles = db.Table(
    'roles',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
)


class User(db.Model, UserMixin):
    # __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    roles = db.relationship(
        'Role', secondary=roles, lazy='subquery', backref=db.backref('users', lazy=True),
    )

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        ser = Serializer(config['SECRET_KEY'])
        try:
            data = ser.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        return User.query.get(data['id'])


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))
