# coding: utf-8

from http import HTTPStatus

from app import db
from app.users import auth, get, http_role_required
from app.users.forms import LoginForm
from app.users.models import Role, User
from flask import (
    Blueprint,
    abort,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
)
from flask_login import login_required, login_user, logout_user

module = Blueprint('users', __name__, url_prefix='/users')


@module.route('/401')
def uri401():
    abort(HTTPStatus.UNAUTHORIZED)


@module.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash('Logged in successfully.')
            next_page = form.next_page.data
            return redirect(next_page or abort(HTTPStatus.BAD_REQUEST))
        flash('Invalid email or password.')
    return render_template('users/login.html', form=form)


@module.route('/token')
@auth.login_required
@http_role_required('token_allowed')
def get_auth_token():
    """Create and get auth token."""
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@module.route('/new', methods=['POST'])
@auth.login_required
@http_role_required('admin')
def new_user():
    """Create user."""
    name = request.json.get('username')
    password = request.json.get('password')
    if name is None or password is None:
        abort(HTTPStatus.BAD_REQUEST)  # missing arguments
    if get(User, name=name) is not None:
        abort(HTTPStatus.CONFLICT)  # existing user

    user = User(name=name)
    user.hash_password(password)
    user.roles.append(Role.query.filter_by(name='default').first())

    db.session.add(user)
    db.session.commit()
    return make_response('User created', HTTPStatus.CREATED)


@module.route('/<name>/delete', methods=['DELETE'])
@auth.login_required
@http_role_required('admin')
def delete_user(name):
    """Delete user."""
    if name is None:
        abort(HTTPStatus.BAD_REQUEST)

    user = get(User, name=name)
    if user is None:
        abort(HTTPStatus.NOT_FOUND)

    db.session.delete(user)
    db.session.commit()
    return make_response('User deleted', HTTPStatus.OK)


@module.route('/roles/new', methods=['POST'])
@auth.login_required
@http_role_required('admin')
def new_role():
    """Create new role."""
    name = request.json.get('name')
    if name is None:
        abort(HTTPStatus.BAD_REQUEST)  # missing arguments
    if get(Role, name=name) is not None:
        abort(HTTPStatus.CONFLICT)  # existing role

    role = Role(name=name)
    db.session.add(role)
    db.session.commit()
    return make_response('Role created', HTTPStatus.CREATED)


@module.route('/<username>/add-role/<role_name>', methods=['UPDATE'])
@auth.login_required
@http_role_required('admin')
def user_role_add(username, role_name):
    """Add role to user."""
    if username is None or role_name is None:
        abort(HTTPStatus.BAD_REQUEST)

    user = get(User, name=username)
    if user is None:
        abort(HTTPStatus.NOT_FOUND)

    role = get(Role, name=role_name)
    if role is None:
        abort(HTTPStatus.NOT_FOUND)

    user.roles.append(role)
    db.session.add(user)
    db.session.commit()
    return make_response('Role added to user', HTTPStatus.OK)


@module.route('/<name>/make-super', methods=['UPDATE'])
@auth.login_required
@http_role_required('super')
def make_super(name):
    """Add all roles to user."""
    if name is None:
        abort(HTTPStatus.BAD_REQUEST)
    user = get(User, name=name)
    if user is None:
        abort(HTTPStatus.NOT_FOUND)
    for role in Role.query.all():
        user.roles.append(role)

    db.session.add(user)
    db.session.commit()
    return make_response('SuperUser born', HTTPStatus.OK)


@module.route('/logout')
@login_required
def logout():
    logout_user()
    return make_response('Logout successfully', HTTPStatus.OK)
