import os
import tempfile
import re
import unittest
from flask import request, url_for
from sqlalchemy.orm.exc import NoResultFound
from wtforms_alchemy import ModelForm
from controller import app
from models import db, User
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


class UserForm(ModelForm):
    class Meta:
        model = User


@app.route('/', methods=['POST'])
def test_controller():
    user = User()
    form = UserForm(request.form)
    form.populate_obj(user)
    return user.name


def test():
    with app.test_request_context():
        with app.test_client() as c:
            rv = c.post('/', data=dict(name='tom'))
            assert rv is not None
            assert rv.status_code == 200


class UserTestCase(unittest.TestCase):
    def setUp(self):
        app.config.from_pyfile('config.cfg', silent=True)
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['CSRF_ENABLED'] = False
        try:
            user = User.query.filter(User.name == 'admin').one()
        except NoResultFound:
            user = User(name='admin', password='admin')
            db.session.add(user)
            db.session.commit()
        self.client = app.test_client()

    def tearDown(self):
        pass

    def testLoginGet(self):
        with app.test_request_context():
            with self.client as c:
                rv = c.get('/login')
                regex1 = re.compile(r'<label\b.*?>.*?</label>')
                regex2 = re.compile(r'''<input\b.*?name=['"]name['"].*?>''')
                assert regex1.search(rv.data)
                assert regex2.search(rv.data)
                assert rv.status_code == 200

    def testLoginPost(self):
        with app.test_request_context():
            with self.client as c:
                rv = c.post(
                    url_for('login'),
                    data=dict(name='admin', password='admin'))
                assert rv.data
                assert rv.status_code == 302

    def testLoginForm(self):
        with app.test_request_context():
            with self.client as c:
                c.post(
                    url_for('login'),
                    data=dict(name='admin', password='admin'))
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
        with app.test_request_context():
            with self.client as c:
                rv = c.get('/index.html')
                assert rv.status_code == 302
                assert 'login' in rv.data
                c.post(
                    '/login', data=dict(name='admin', password='admin'))
                rv = c.get('/index.html')
                assert rv.status_code == 200
                c.get('/logout')
                rv = c.get('index.html')
                assert rv.status_code == 302


def run_test():
    db.create_all()
    unittest.main()
