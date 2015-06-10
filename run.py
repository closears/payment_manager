# coding=utf-8
import os
from models import User, Role
from controller import app, db


def init():
    config_file = os.path.join(
        os.path.abspath(
            os.path.dirname(__file__)),
        'config.cfg')
    app.config.from_pyfile(config_file, silent=True)
    db.create_all()
    try:
        user = User.query.filter(
            User.name == 'admin').one()
    except:
        user = User(name='admin', password='admin')
        db.session.add(user)
        db.session.commit()
    try:
        role = Role.query.filter(
            Role.name == 'admin').one()
    except:
        role = Role(name='admin')
        db.session.add(role)
        db.session.commit()
    if not user.has_role('admin'):
        user.roles.append(role)
        db.session.commit()

if __name__ == '__main__':
    init()
    app.run()
