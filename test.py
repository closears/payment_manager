'''
import os
import tempfile
import unittest


class FlaskrTestCase(unittest.TestCase):

    def setUp(self):
        os.environ['FLASKR_SETTINGS'] = 'config.cfg'
        self.db_fd, flaskr.app.config['DATABASE'] = tempfile.mkstemp()
        flaskr.app.config['TESTING'] = True
        self.app = flaskr.app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(flaskr.app.config['DATABASE'])

    def test_not_empty(self):
        assert self.app.get('/') is not None
'''
import re
import unittest
from flask import request
from sqlalchemy.orm.exc import NoResultFound
from wtforms_alchemy import ModelForm
from controller import app
from models import db, User


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
                    '/login', data=dict(name='admin', password='admin'))
                assert rv.status_code == 200


def run_test():
    unittest.main()
