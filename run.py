# coding=utf-8
from models import User, Role
from controller import app, db


def init():
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
    app.config.from_pyfile('config.cfg', silent=True)
    init()
    app.run()
