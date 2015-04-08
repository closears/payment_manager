import os
import tempfile
import flaskr
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
