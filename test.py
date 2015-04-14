import os
import tempfile
import unittest
from flask_testing import TestCase
from flask import request, url_for
from sqlalchemy.orm.exc import NoResultFound
from wtforms_alchemy import ModelForm
from controller import app, db
from models import User
from forms import LoginForm


class Utils(object):

    class __Tempfile(object):

        def __init__(self):
            self.fd, self.filename = None, None

        def mktemp(self):
            self.fd, self.filename = tempfile.mkstemp()
            return self

        def close(self):
            os.close(self.fd)
            os.unlink(self.filename)

    tempFileMaker = __Tempfile()

    @classmethod
    def is_authorized(cls, client):
        rv = client.get('/index.html')
        return rv.status_code == 200


class UserForm(ModelForm):
    class Meta:
        model = User


@app.route('/test', methods=['POST'])
def test_controller():
    user = User()
    form = UserForm(request.form)
    form.populate_obj(user)
    return user.name


def test():
    with app.test_request_context():
        with app.test_client() as c:
            rv = c.post('/test', data=dict(name='tom'))
            assert rv is not None
            assert rv.status_code == 200


class UserTestCase(TestCase):
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    TESTING = True

    def create_app(self):
        app.config.from_pyfile('config.cfg', silent=True)
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['CSRF_ENABLED'] = False
        return app

    def setUp(self):
        self.create_app()
        db.create_all()
        try:
            user = User.query.filter(User.name == 'admin').one()
        except NoResultFound:
            user = User(name='admin', password='admin')
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def testLoginGet(self):

        rv = self.client.get('/login')
        assert '<input' in rv.data
        assert 'name=' in rv.data
        self.assert_200(rv)

    def testLoginPost(self):
        assert not Utils.is_authorized(self.client)
        rv = self.client.post(
            url_for('login', next='/success'),
            data=dict(name='admin', password='admin'))
        self.assert_status(rv, 302)
        assert Utils.is_authorized(self.client)

    def testLoginForm(self):
        from werkzeug import MultiDict
        form = LoginForm(
            MultiDict([('name', 'admin'), ('password', 'admin')]))
        assert form.validate()
        user = User()
        form.populate_obj(user)
        assert user.name
        assert user.password
        assert user.is_active
        assert not user.roles

    def testLogout(self):
        rv = self.client.get('/index.html')
        self.assert_status(rv, 302)
        assert 'login' in rv.data
        self.client.post(
            url_for('login', next='/success'),
            data=dict(name='admin', password='admin'))
        assert Utils.is_authorized(self.client)
        self.client.get('/logout')
        assert not Utils.is_authorized(self.client)

    def testChangePassword(self):
        self.client.get('/logout')
        rv = self.client.get('/user/changepassword')
        self.assert_status(rv, 302)
        rv = self.client.post(
            '/login', data=dict(name='admin', password='admin'))
        assert Utils.is_authorized(self.client)
        rv = self.client.post(
            '/user/changepassword',
            data=dict(
                oldpassword='admin',
                newpassword='123123',
                confirm='123123')
        )
        self.assert200(rv)
        assert Utils.is_authorized(self.client)
        user = User.query.filter(User.name == 'admin').one()
        assert user == User(name='admin', password='123123')


def run_test():
    db.create_all()
    unittest.main()
