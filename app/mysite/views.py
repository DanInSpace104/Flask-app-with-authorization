# coding: utf-8

from http import HTTPStatus

from app.users import auth, http_role_required, role_required
from flask import Blueprint, make_response, render_template, url_for
from flask_login import login_required

module = Blueprint('mysite', __name__, url_prefix='/mysite')


@module.route('/')
def index():
    return render_template('mysite/index.html')


@module.route('/login-required')
@login_required
def needs_login():
    return render_template('mysite/index.html')
