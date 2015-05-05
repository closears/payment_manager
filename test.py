import os
from datetime import date
import tempfile
import unittest
from werkzeug import MultiDict
from flask_testing import TestCase
from flask import request, url_for
from sqlalchemy.orm.exc import NoResultFound
from wtforms_alchemy import ModelForm
from controller import app, db
from models import User, Role, Address, Person
from forms import LoginForm, AdminAddRoleForm, PersonForm


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


class TestBase(TestCase):

    def create_app(self):
        app.config.from_pyfile('config.cfg', silent=True)
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['CSRF_ENABLED'] = False
        return app

    def setUp(self):
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

    def assert_authorized(self):
        rv = self.client.get('/index.html')
        self.assert200(rv)

    def assert_not_authorized(self):
        rv = self.client.get('/index.html')
        self.assert_status(rv, 302)


class UserTestCase(TestBase):
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    TESTING = True

    def testLoginGet(self):
        rv = self.client.get('/login')
        assert '<input' in rv.data
        assert 'name=' in rv.data
        self.assert_200(rv)
        self.assert_not_authorized()

    def testLoginPost(self):
        self.assert_not_authorized()
        rv = self.client.post(
            url_for('login', next='/success'),
            data=dict(name='admin', password='admin'))
        self.assert_status(rv, 302)
        self.assert_authorized()

    def testLoginForm(self):

        form = LoginForm(
            MultiDict([('name', 'admin'), ('password', 'admin')]))
        self.assertTrue(form.validate())
        user = User()
        form.populate_obj(user)
        self.assertEqual(user.name, 'admin')
        self.assertEqual(User(password='admin').password, user.password)
        self.assertTrue(user.is_active)
        self.assertTrue(not user.roles)

    def testLogout(self):
        self.assert_not_authorized()
        self.client.post(
            url_for('login', next='/success'),
            data=dict(name='admin', password='admin'))
        self.assert_authorized()
        self.client.get('/logout')
        self.assert_not_authorized()

    def testChangePassword(self):
        self.client.get('/logout')
        rv = self.client.get('/user/changepassword')
        self.assert_status(rv, 302)
        self.client.post(
            '/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        self.client.get('/user/changepassword')
        self.assert_template_used('changepassword.html')
        data = dict(
            oldpassword='admin',
            newpassword='123123',
            confirm='12312')
        self.client.post('/user/changepassword', data=data)
        self.assert_template_used('changepassword.html')
        self.assertNotIn('success', rv.data)
        self.assert_authorized()
        data.update(confirm='123123')
        self.client.post('/user/changepassword', data=data)
        self.assert_authorized()
        user = User.query.filter(User.name == 'admin').one()
        self.assertEqual(User(password='123123').password, user.password)
        data.update(oldpassword='admin')
        self.client.post('/user/changepassword', data=data)
        self.assert_not_authorized()
        self.client.post(
            '/login', data=dict(name='admin', password='123123'))
        self.assert_authorized()
        data.update(oldpassword='123123', newpassword='admin', confirm='admin')
        self.client.post(
            '/user/changepassword', data=data)


class AdminTestCase(TestBase):

    def setUp(self):
        super(AdminTestCase, self).setUp()
        user = User.query.filter(User.name == 'admin').one()
        user.roles.append(Role(name='admin'))
        db.session.commit()

    def test_user_form(self):
        self.assertIsNotNone(UserForm().data)

    def test_add_user(self):
        self.assert_not_authorized()
        self.client.post(
            '/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        rv = self.client.get('/admin/user/add')
        self.assertIn('<form', rv.data)
        self.client.post(
            '/admin/user/add', data=dict(
                name='test',
                password='test',
                active=True
            ))
        user = User.query.filter(User.name == 'test').one()
        self.assertEqual(user.name, 'test')

    def test_remove_user(self):
        self.assert_not_authorized()
        self.client.post(
            '/login', data=dict(name='admin', password='admin'))
        rv = self.client.get('/admin/user/add')
        self.assertIn('<form', rv.data)
        self.client.post(
            '/admin/user/add', data=dict(
                name='test2',
                password='test2',
                active=True))
        user = User.query.filter(User.name == 'test2').one()
        self.client.post(url_for('admin_remove_user', pk=user.id))
        self.assertTrue(not User.query.filter(User.name == 'test2').all())
        rv = self.client.post(url_for('admin_remove_user', pk=user.id))
        self.assert404(rv)

    def test_admin_user_inactivate(self):
        self.assert_not_authorized()
        self.client.post('/login', data=dict(
            name='admin',
            password='admin'))
        self.assert_authorized()
        user = User(name='test', password='test')
        db.session.add(user)
        db.session.commit()
        self.assertTrue(user.active)
        rv = self.client.get(url_for('admin_user_inactivate', pk=user.id))
        self.assertIn('submit', rv.data)
        self.client.post(url_for('admin_user_inactivate', pk=user.id))
        user = User.query.get(user.id)
        self.assertFalse(user.active)
        rv = self.client.post(url_for('admin_user_activate', pk=user.id))
        self.assertIn('success', rv.data)
        user = User.query.get(user.id)
        self.assertTrue(user.active)
        db.session.delete(user)
        db.session.commit()

    def test_admin_user_changpassword(self):
        self.client.post('/login', data=dict(
            name='admin', password='admin'))
        self.assert_authorized()
        user = User(name='test', password='test')
        db.session.add(user)
        db.session.commit()
        rv = self.client.get(url_for('admin_user_changepassword', pk=user.id))
        self.assertIn('<form', rv.data)
        rv = self.client.get(url_for('admin_user_changepassword', pk=100))
        self.assert404(rv)
        self.client.post(
            url_for('admin_user_changepassword', pk=user.id),
            data=dict(newpassword='123123', confirm='123123')
        )
        user = User.query.get(user.id)
        self.assertEqual(User(password='123123').password, user.password)
        db.session.delete(user)
        db.session.commit()

    def test_admin_user_add_role_form(self):
        role = Role(name='test')
        db.session.add(role)
        db.session.commit()
        user = User.query.filter(User.name == 'admin').one()
        form = AdminAddRoleForm(user=user)
        self.assertIn('test', form.role())
        db.session.delete(role)
        db.session.commit()

    def test_admin_user_add_and_romove_role(self):
        user = User(name='test', password='test')
        role = Role(name='test')
        role1 = Role(name='test1')
        db.session.add(role1)
        db.session.add(role)
        db.session.add(user)
        db.session.commit()

        self.client.post('/login', data=dict(
            name='admin',
            password='admin'))
        self.assert_authorized()
        rv = self.client.get(url_for('admin_user_add_role', pk=user.id))
        self.assertIn('<select', rv.data)
        self.client.post(url_for('admin_user_add_role', pk=user.id),
                         data=dict(role=role.id))
        user = User.query.get(user.id)
        self.assertIn(role, user.roles)
        self.client.post(url_for('admin_user_add_role', pk=user.id),
                         data=dict(role=role1.id))
        user = User.query.get(user.id)
        self.assertIn(role1, user.roles)
        self.client.post(url_for('admin_user_remove_role', pk=user.id),
                         data=dict(role=role1.id))
        user = User.query.get(user.id)
        self.assertNotIn(role1, user.roles)
        user.roles = []
        db.session.commit()
        db.session.delete(user)
        db.session.delete(role)
        db.session.delete(role1)
        db.session.commit()

    def test_admin_user_detail(self):
        user = User.query.filter(User.name == 'admin').one()
        role = Role(name='test')
        db.session.add(role)
        self.assert_not_authorized()
        self.client.post('/login', data=dict(
            name='admin',
            password='admin'))
        self.assert_authorized()
        self.client.post(url_for('admin_user_add_role', pk=user.id),
                         data=dict(role=role.id))
        self.assertIn(role, user.roles)
        rv = self.client.get(url_for('admin_user_detail', pk=user.id))
        self.assertIn('admin', rv.data)
        self.assertIn('test', rv.data)
        user.roles.remove(role)
        db.session.commit()
        db.session.delete(role)
        db.session.commit()

    def test_user_search(self):
        for i in range(30):
            user = User(name='test{}'.format(i), password='test')
            db.session.add(user)
            role = Role(name='test{}'.format(i))
            user.roles.append(role)
            db.session.commit()

        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get(
            url_for('admin_user_search', name='test', page=1, per_page=20))

        users = User.query.filter(User.name.like('test%')).all()
        for user in users:
            user.roles = []
            db.session.commit()
            db.session.delete(user)
        db.session.commit()

    def test_admin_add_role(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('admin_role_add'))
        self.assert_200(rv)
        self.client.post(url_for('admin_role_add'), data=dict(name='test'))
        role = Role.query.filter(Role.name == 'test').one()
        self.assertEqual(role.name, 'test')

    def test_admin_remove_role(self):
        role = Role(name='test')
        db.session.add(role)
        db.session.commit()
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('admin_role_remove', pk=role.id))
        self.assert_200(rv)
        self.assertIn('<form', rv.data)
        self.assertIsNotNone(Role.query.get(role.id))
        self.client.post(url_for('admin_role_remove', pk=role.id))
        self.assertIsNone(Role.query.get(role.id))

    def test_admin_search_log(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        admin = User.query.filter(User.name == 'admin').one()
        rv = self.client.get(url_for(
            'admin_log_search',
            operator_id=admin.id,
            start_date='2015-01-01',
            end_date='2015-12-31',
            page=1,
            per_page=20))
        self.assertIn('login', rv.data)

    def test_admin_log_clean(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        admin = User.query.filter(User.name == 'admin').one()
        rv = self.client.get(url_for(
            'admin_log_search',
            operator_id=admin.id,
            start_date='2015-01-01',
            end_date='2015-12-31',
            page=1,
            per_page=20))
        self.assertIn('login', rv.data)
        rv = self.client.get(url_for('admin_log_clean', operator_id=admin.id))
        self.assertIn('<form', rv.data)
        self.assertIn('start_date', rv.data)
        self.client.post(
            url_for('admin_log_clean', operator_id=admin.id),
            data=dict(
                start_date='2011-01-01',
                end_date='2012-01-01'))
        self.assertTrue(admin.logs)
        self.client.post(
            url_for('admin_log_clean', operator_id=admin.id),
            data=dict(
                start_date='2015-01-01',
                end_date='2015-12-31'))
        self.assertFalse(admin.logs)


class AddressTestCase(TestBase):
    def setUp(self):
        super(AddressTestCase, self).setUp()
        parent = Address(no='420525', name='parent')
        child1 = Address(no='42052511', name='child1')
        child11 = Address(no='42052511001', name='child11')
        child12 = Address(no='42052511002', name='child12')
        child1.childs.extend([child11, child12])
        child2 = Address(no='42052512', name='child2')
        child21 = Address(no='42052512001', name='child21')
        child22 = Address(no='42052512002', name='child22')
        child2.childs.extend([child21, child22])
        db.session.add(parent)
        parent.childs.extend([child1, child2])
        admin = User.query.filter(User.name == 'admin').one()
        admin.roles.append(Role(name='admin'))
        admin.address = parent
        db.session.commit()

    def test(self):
        admin = User.query.filter(User.name == 'admin').one()
        self.assertEqual(2, len(admin.address.childs))
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        rv = self.client.get(url_for('address_add'))
        self.assert200(rv)

    def test_address_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        parent = Address.query.filter(Address.name == 'child1').one()
        self.client.get(url_for('address_add'))
        self.client.post(url_for('address_add'), data=dict(
            no='42052511xxx',
            name='test',
            parent_id=parent.id))
        address = Address.query.filter(Address.name == 'test').one()
        self.assertIn(address, parent.descendants)
        self.assertEqual(address.no, '42052511xxx')
        db.session.delete(address)
        db.session.commit()

    def test_address_delete(self):
        child3 = Address(no='42052513', name='child3')
        child31 = Address(no='42052513001', name='child31')
        child32 = Address(no='42052513002', name='child32')
        child3.childs.extend([child31, child32])
        db.session.add(child3)
        db.session.commit()

        self.assertIsNotNone(Address.query.get(child3.id))
        self.assertIsNotNone(Address.query.get(child31.id))
        self.assertIsNotNone(Address.query.get(child32.id))

        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('address_delete', pk=child3.id))
        self.assertIn('confirm', rv.data)
        self.client.post(url_for('address_delete', pk=child3.id))
        self.assertIsNone(Address.query.get(child3.id))
        self.assertIsNone(Address.query.get(child31.id))
        self.assertIsNone(Address.query.get(child32.id))

    def test_address_edit(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('address_add'), data=dict(
            no='42052519', name='test_p'))
        parent = Address.query.filter(Address.name == 'test_p').one()
        self.client.post(url_for('address_add'), data=dict(
            no='42052519001', name='test_c', parent_id=parent.id))
        address = Address.query.filter(Address.name == 'test_c').one()
        self.assertEqual(parent.id, address.parent_id)
        rv = self.client.get(url_for('address_edit', pk=address.id))
        self.assertIn('test_c', rv.data)
        self.client.post(url_for('address_edit', pk=address.id), data=dict(
            no='42052519001', name='child2', parent_id=parent.id))
        self.assertEqual('test_c', address.name)
        self.client.post(url_for('address_delete', pk=parent.id))
        self.assertIsNone(Address.query.get(address.id))

    def test_address_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for(
            'address_search', name='child', page=1, per_page=2))
        self.assertIn('tbody', rv.data)


class PersonTestCase(TestBase):

    def setUp(self):
        super(PersonTestCase, self).setUp()
        parent = Address(no='420525', name='parent')
        child1 = Address(no='42052511', name='child1')
        child11 = Address(no='42052511001', name='child11')
        child12 = Address(no='42052511002', name='child12')
        child1.childs.extend([child11, child12])
        child2 = Address(no='42052512', name='child2')
        child21 = Address(no='42052512001', name='child21')
        child22 = Address(no='42052512002', name='child22')
        child2.childs.extend([child21, child22])
        db.session.add(parent)
        parent.childs.extend([child1, child2])
        self.admin = User.query.filter(User.name == 'admin').one()
        self.admin.roles.append(Role(name='admin'))
        self.admin.address = parent
        db.session.commit()

    def __add_person(self, idcard, birthday, name, address_id):
        from uuid import uuid4
        self.client.post(url_for('person_add'), data=dict(
            idcard=idcard,
            birthday=birthday,
            name=name,
            address_id=address_id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))

    def __remove_person(self, pk):
        self.client.post(url_for('person_delete', pk=pk))

    def test(self):
        person = Person()
        person.birthday = date(1951, 7, 1)
        person.reg()
        self.assertIsNotNone(person.status)

    def test_person_form(self):
        form = PersonForm(self.admin, formdata=MultiDict([
            ('idcard', '420525195107010010'),
            ('birthday', '1951-07-01'),
            ('name', 'test'),
            ('address_id', self.admin.address.id),
            ('address_detail', 'xxx'),
            ('securi_no', '123123'),
            ('personal_wage', '0.94')]))
        person = Person()
        form.populate_obj(person)
        self.assertEqual(person.idcard, '420525195107010010')
        self.assertEqual(person.birthday, date(1951, 7, 1))

    def test_person_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('person_add'))
        self.assert_200(rv)
        address = Address.query.filter(Address.name == 'parent').one()
        self.__add_person(
            '420525195107010010', '1951-07-01', 'test', address.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.assertIsNotNone(person)
        db.session.delete(person)
        db.session.commit()

    def test_person_delete(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        address = Address.query.filter(Address.name == 'parent').one()
        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010010',
            birthday='1951-07-01',
            name='test',
            address_id=address.id,
            address_detail='xxxx',
            securi_no='123123',
            personal_wage='0.94'))
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.assertIsNotNone(person)
        self.assertEqual(Person.STATUS_CHOICES[Person.REG][0], person.status)
        persons = Person.query.filter(Person.id == person.id).all()
        self.assertTrue(persons)
        rv = self.client.get(url_for('person_delete', pk=person.id))
        self.assertIn('delete', rv.data)
        self.client.post(url_for('person_delete', pk=person.id))
        persons = Person.query.filter(Person.id == person.id).all()
        self.assertFalse(persons)

    def test_person_normal_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.assertTrue(person.can_retire)
        self.__remove_person(person.id)

    def test_person_retire_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.client.post(url_for('person_regire_reg', pk=person.id), data={
            'date': '2011-08-01'})
        self.assertEqual(date(2011, 8, 1), person.retire_day)
        self.__remove_person(person.id)

    def test_person_batch_normal(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        map(lambda x: self.__add_person(
            '4205251951070100{:0>2}'.format(x),
            '1951-07-{:0>2}'.format(x), 'test{}'.format(x), addr.id),
            range(10))
        self.assertGreaterEqual(Person.query.filter(
            Person.idcard.like('420525195107%')).all(), 10)
        self.assertIn('420525195107',
                      [p.idcard[:12] for p in Person.query.all()])
        self.client.post(url_for('person_batch_normal'), data=dict(
            start_date='1951-07-01', end_date='1951-07-31'))
        for person in Person.query.filter(
                Person.idcard.like('420525195107%')).all():
            self.assertTrue(person.can_retire)
        map(lambda x: self.__remove_person(x),
            [p.id for p in
             Person.query.filter(Person.idcard.like('420525195107%')).all()])
        self.assertNotIn('420525195107',
                         [p.idcard[:12] for p in Person.query.all()])

    def test_person_dead_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(url_for('person_dead_reg', pk=person.id),
                              data=dict(date='2015-07-01'))
        self.assert500(rv)
        self.assertFalse(person.can_retire)
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.assertTrue(person.can_retire)
        self.client.post(url_for('person_dead_reg', pk=person.id),
                         data=dict(date='2015-07-01'))
        self.assertEqual(person.dead_day, date(2015, 7, 1))
        self.__remove_person(person.id)
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.client.post(url_for('person_regire_reg', pk=person.id),
                         data=dict(date='2011-08-01'))
        self.assertTrue(person.can_dead_retire)
        self.client.post(url_for('person_dead_reg', pk=person.id),
                         data=dict(date='2015-07-01'))
        self.assertEqual(person.dead_day, date(2015, 7, 1))
        self.__remove_person(person.id)

    def test_person_abort_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(url_for('person_abort_reg', pk=person.id))
        self.assert500(rv)
        rv = self.client.post(url_for('person_normal_reg', pk=person.id))
        self.assert200(rv)
        rv = self.client.post(url_for('person_abort_reg', pk=person.id))
        self.assert200(rv)
        self.assertFalse(person.can_retire)
        self.assertFalse(person.can_normal)
        self.__remove_person(person.id)

    def test_person_suspend_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(url_for('person_suspend_reg', pk=person.id))
        self.assert403(rv)
        self.client.post(url_for('admin_role_add'),
                         data=dict(name='person_admin'))
        role = Role.query.filter(Role.name == 'person_admin').one()
        self.client.post(url_for('admin_user_add_role', pk=self.admin.id),
                         data=dict(role=role.id))
        rv = self.client.post(url_for('person_suspend_reg', pk=person.id))
        self.assert200(rv)
        self.assertTrue(person.can_resume)
        self.client.post(url_for('admin_user_remove_role', pk=self.admin.id),
                         data=dict(role=role.id))
        self.client.post(url_for('admin_role_remove', pk=role.id))
        self.__remove_person(person.id)

    def test_person_resume_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        addr = Address.query.filter(Address.name == 'parent').one()
        self.__add_person('420525195107010010', '1951-07-01', 'test', addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(url_for('person_resume_reg', pk=person.id))
        self.assert403(rv)
        self.client.post(url_for('admin_role_add'),
                         data=dict(name='person_admin'))
        role = Role.query.filter(Role.name == 'person_admin').one()
        self.client.post(url_for('admin_user_add_role', pk=self.admin.id),
                         data=dict(role=role.id))
        rv = self.client.post(url_for('person_resume_reg', pk=person.id))
        self.assert200(rv)
        self.assertTrue(person.can_suspend)
        self.client.post(url_for('admin_user_remove_role', pk=self.admin.id),
                         data=dict(role=role.id))
        self.client.post(url_for('admin_role_remove', pk=role.id))
        self.__remove_person(person.id)
    

def run_test():
    db.create_all()
    unittest.main()
