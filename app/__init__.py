from flask import Flask, g
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
login = LoginManager()
bootstrap = Bootstrap(app)

app.config.from_object('config.DevelopmentConfig')

config = app.config

db = SQLAlchemy(app)
with app.test_request_context():
    db.create_all()
migrate = Migrate(app, db)

from app.mysite import views as mysite
from app.users import views as users

app.register_blueprint(users.module)
app.register_blueprint(mysite.module)

login.init_app(app)
login.login_view = 'users.login'


@app.before_request
def before_request():
    g.user = current_user
