from http import HTTPStatus

from flask import abort, g
from flask_httpauth import HTTPBasicAuth
from flask_login import current_user

from .models import Role, User

auth = HTTPBasicAuth()


def get(Model, **kwargs):
    return Model.query.filter_by(**kwargs).first()


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = get(User, name=username_or_token)
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def role_required(role_name):
    def role_decorator(func):
        def wrapper(*args, **kwargs):
            if get(Role, name=role_name) not in current_user.roles:
                return abort(HTTPStatus.FORBIDDEN)
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return role_decorator


def http_role_required(role_name):
    def role_decorator(func):
        def wrapper(*args, **kwargs):
            if get(Role, name=role_name) not in g.user.roles:
                return abort(HTTPStatus.FORBIDDEN)
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return role_decorator
