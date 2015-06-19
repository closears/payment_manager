import os
import io
from datetime import date, datetime, timedelta
from uuid import uuid4
import tempfile
import unittest
from werkzeug import MultiDict
from flask_testing import TestCase
from flask import url_for
from sqlalchemy.orm.exc import NoResultFound
from wtforms_alchemy import ModelForm
from models import (User, Role, Address, Person, Standard, Bankcard,
                    Note, PayBookItem, PayBook, OperationLog)
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


def _create_persons(idcard_prefix, count, address, create_by):
    from uuid import uuid4
    persons = [Person(
        idcard='{}{:0>4}'.format(idcard_prefix[:14], x),
        name='test',
        birthday=date(1951, 7, 1),
        address=address,
        address_detail='xxx',
        securi_no=uuid4().hex,
        personal_wage=0.94,
        create_by=create_by) for x in range(1, count + 1)]
    map(lambda p: p.reg(), persons)
    return persons


class UserForm(ModelForm):
    class Meta:
        model = User


class TestBase(TestCase):
    def _get_or_create(self, model_class, key, value, **kwargs):
        if isinstance(key, str):
            key = getattr(model_class, key)
        try:
            result = self.session.query(model_class).filter(
                key == value).one()
        except NoResultFound:
            result = model_class(**kwargs)
            self.session.add(result)
            self.session.commit()
        return result

    def _del_all_instance(self, model_class):
        self.session.query(model_class).delete()
        self.session.commit()

    def create_app(self):
        from controller import app
        app.config.from_pyfile('config.cfg', silent=True)
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['CSRF_ENABLED'] = False
        return app

    def setUp(self):
        from controller import db
        if not db.engine.has_table('users'):
            db.create_all()

        self.connect = db.engine.begin()
        self.session = db.session
        user = self._get_or_create(
            User, 'name', 'admin', name='admin', password='admin')
        if not user.has_role('admin'):
            role = self._get_or_create(
                Role, 'name', 'admin', name='admin')
            user.roles.append(role)
            self.session.commit()
        self.admin = user
        self.db = db

    def tearDown(self):
        self.db.session.remove()

    def assert_authorized(self):
        rv = self.client.get('/index.html')
        self.assert200(rv)

    def assert_not_authorized(self):
        rv = self.client.get('/index.html')
        self.assert_status(rv, 302)

    @property
    def yestoday(self):
        return datetime.now().date() + timedelta(days=-1)

    @property
    def yestoday_str(self):
        return datetime.strftime(self.yestoday, '%Y-%m-%d')

    @property
    def today(self):
        return datetime.now().date()

    @property
    def today_str(self):
        return datetime.strftime(self.today, '%Y-%m-%d')

    @property
    def tomorrow(self):
        return (datetime.now() + timedelta(days=1)).date()

    @property
    def tomorrow_str(self):
        return datetime.strftime(self.tomorrow, '%Y-%m-%d')

    def _days_tomorrow(self, day):
        day += timedelta(days=1)
        if isinstance(day, datetime):
            day = day.date()
        return day

    def _days_tomorrow_str(self, day):
        return datetime.strftime(self._days_tomorrow(day), '%Y-%m-%d')


class UserTestCase(TestBase):

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
            url_for('admin_add_user'),
            data=dict(
                name='test',
                password='test',
                active=True
            ))
        user = self._get_or_create(User, 'name', 'test')
        self.assertEqual(user.name, 'test')
        self.session.query(User).delete()
        self.session.commit()

    def test_remove_user(self):
        self.assert_not_authorized()
        self.client.post(
            '/login', data=dict(name='admin', password='admin'))
        rv = self.client.get('/admin/user/add')
        self.assertIn('<form', rv.data)
        self.client.post(
            url_for('admin_add_user'),
            data=dict(
                name='test2',
                password='test2',
                active=True))
        user = self._get_or_create(User, 'name', 'test2')
        self.client.post(url_for('admin_remove_user', pk=user.id))
        self.assertTrue(not User.query.filter(User.name == 'test2').all())
        rv = self.client.post(url_for('admin_remove_user', pk=user.id))
        self.assert404(rv)
        self.session.query(User).delete()
        self.session.commit()

    def test_admin_user_inactivate(self):
        self.assert_not_authorized()
        self.client.post('/login', data=dict(
            name='admin',
            password='admin'))
        self.assert_authorized()
        user = self._get_or_create(
            User, 'name', 'test', name='test', password='test')
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
        self.session.query(User).delete()
        self.session.commit()

    def test_admin_user_changpassword(self):
        self.client.post('/login', data=dict(
            name='admin', password='admin'))
        self.assert_authorized()
        user = self._get_or_create(
            User, 'name', 'test', name='test', password='test')
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
        self.session.query(User).delete()
        self.session.commit()

    def test_admin_user_add_role_form(self):
        self._get_or_create(Role, 'name', 'test', name='test')
        user = User.query.filter(User.name == 'admin').one()
        form = AdminAddRoleForm(user=user)
        self.assertIn('test', form.role())
        self.session.query(Role).delete()
        self.session.commit()

    def test_admin_user_add_and_romove_role(self):
        user = User(name='test', password='test')
        role = Role(name='test')
        role1 = Role(name='test1')
        self.session.add(role1)
        self.session.add(role)
        self.session.add(user)
        self.session.commit()

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
        self.session.commit()
        self._del_all_instance(User)
        self._del_all_instance(Role)

    def test_admin_user_detail(self):
        user = User.query.filter(User.name == 'admin').one()
        role = Role(name='test')
        self.session.add(role)
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
        self._del_all_instance(User)
        self._del_all_instance(Role)

    def test_user_search(self):
        for i in range(30):
            user = User(name='test{}'.format(i), password='test')
            self.session.add(user)
            role = Role(name='test{}'.format(i))
            user.roles.append(role)
            self.session.commit()
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(
            url_for('admin_user_search', name='test', page=1, per_page=30))
        self.assertIn('test0', rv.data)
        self.assertIn('test29', rv.data)
        self._del_all_instance(User)
        self._del_all_instance(Role)

    def test_admin_add_role(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('admin_role_add'))
        self.assert_200(rv)
        self.client.post(url_for('admin_role_add'), data=dict(name='test'))
        role = Role.query.filter(Role.name == 'test').one()
        self.assertEqual(role.name, 'test')
        self._del_all_instance(Role)

    def test_admin_remove_role(self):
        role = Role(name='test')
        self.session.add(role)
        self.session.commit()
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('admin_role_remove', pk=role.id))
        self.assert_200(rv)
        self.assertIn('<form', rv.data)
        self.assertIsNotNone(Role.query.get(role.id))
        self.client.post(url_for('admin_role_remove', pk=role.id))
        self.assertIsNone(Role.query.get(role.id))

    def test_admin_search_log(self):
        self._del_all_instance(OperationLog)
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        rv = self.client.get(url_for(
            'admin_log_search',
            operator_name='admin',
            start_date='2015-01-01',
            end_date='2015-12-31',
            page=1,
            per_page=20))
        self.assertIn('login', rv.data)

    def test_admin_log_clean(self):
        self._del_all_instance(OperationLog)
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


class AddressDataMixin(object):
    def __init__(self):

        def get_or_create(no, name=None):
            try:
                result = self.session.query(Address).filter(
                    Address.no == no).one()
            except NoResultFound:
                result = Address(no=no, name=name)
                self.session.add(result)
                self.session.commit()
            return result
        self.parent_addr = get_or_create(no='420525', name='parent')

        self.child1_addr, self.child11_addr, self.child12_addr = map(
            lambda args: get_or_create(args[0], args[1]),
            (
                ('42052511', 'child1'),
                ('42052511001', 'child11'),
                ('42052511002', 'child12'),
            ))
        self.child2_addr, self.child21_addr, self.child22_addr = map(
            lambda args: get_or_create(args[0], args[1]),
            (
                ('42052512', 'child2'),
                ('42052512001', 'child21'),
                ('42052512002', 'child22'),
            ))
        self.parent_addr.childs.extend([self.child1_addr, self.child2_addr])
        self.child1_addr.childs.extend([self.child11_addr, self.child12_addr])
        self.child2_addr.childs.extend([self.child21_addr, self.child22_addr])
        self.db.session.commit()


class AddressTestCase(TestBase, AddressDataMixin):

    def setUp(self):
        TestBase.setUp(self)
        AddressDataMixin.__init__(self)

        if not self.admin.has_role('admin'):
            role = self._get_or_create(
                Role, 'name', 'admin', name='admin')
            self.admin.roles.append(role)
        self.admin.address = self.parent_addr
        self.session.commit()

    def test(self):
        self.assertEqual(2, len(self.admin.address.childs))
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        rv = self.client.get(url_for('address_add'))
        self.assert200(rv)

    def test_address_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.assert_authorized()
        parent = self.child1_addr
        self.client.get(url_for('address_add'))
        self.client.post(url_for('address_add'), data=dict(
            no='42052511xxx',
            name='test',
            parent_id=parent.id))
        address = Address.query.filter(Address.name == 'test').one()
        self.assertIn(address, parent.descendants)
        self.assertEqual(address.no, '42052511xxx')
        self.client.post(url_for('address_add'), data=dict(
            no='42052511yyy',
            name='test2',
            parent_id=''))
        address = Address.query.filter(
            Address.name == 'test2').one()
        self.assertFalse(address.parent)
        self.session.query(Address).delete()
        self.session.commit()

    def test_address_delete(self):
        child3 = Address(no='42052513', name='child3')
        child31 = Address(no='42052513001', name='child31')
        child32 = Address(no='42052513002', name='child32')
        child3.childs.extend([child31, child32])
        self.session.add(child3)
        self.session.commit()

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


class PersonAddRemoveMixin(object):
    def _add_person(self, idcard, birthday, name, address_id):
        from uuid import uuid4
        birthday = (isinstance(birthday, date) and birthday or
                    date.fromordinal(
                        datetime.strptime(birthday, '%Y-%m-%d').toordinal()))
        person = Person(
            idcard=idcard,
            birthday=birthday,
            name=name,
            address_id=address_id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            create_by=self.admin)
        person.reg()
        self.session.add(person)
        self.session.commit()

    def _remove_person(self, pk):
        self.session.query(Person.id == pk).delete()
        self.session.commit()


class PersonTestBase(TestBase, PersonAddRemoveMixin, AddressDataMixin):

    def setUp(self):
        TestBase.setUp(self)
        AddressDataMixin.__init__(self)
        PersonAddRemoveMixin.__init__(self)
        self.admin.address = self.parent_addr
        self.session.commit()


class PersonTestCase(PersonTestBase):
    def test(self):
        person = Person()
        person.birthday = date(1951, 7, 1)
        person.reg()
        self.assertIsNotNone(person.status)

    def test_person_form(self):
        self._del_all_instance(Person)
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
        self._del_all_instance(Person)
        rv = self.client.get(url_for('person_add'))
        self.assert_200(rv)
        self._add_person(
            '420525195107010010', '1951-07-01', 'test', self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.assertIsNotNone(person)
        self._del_all_instance(Person)

        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010010',
            name='test',
            birthday='1951-07-01',
            address_id=self.admin.address_id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.assertIsNotNone(person)
        self._del_all_instance(Person)
        person_count = Person.query.filter(
            Person.idcard == '420525195107010010').count()
        self.assertEqual(0, person_count)
        self._del_all_instance(Person)

    def test_person_delete(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.assert_authorized()
        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010010',
            birthday='1951-07-01',
            name='test',
            address_id=self.parent_addr.id,
            address_detail='xxxx',
            securi_no='123123',
            personal_wage='0.94'))
        person = self._get_or_create(
            Person, 'idcard', '420525195107010010')
        self.assertIsNotNone(person)
        self.assertTrue(person.can_normal)
        persons = self.session.query(Person).filter(
            Person.id == person.id).all()
        self.assertTrue(persons)
        rv = self.client.get(url_for('person_delete', pk=person.id))
        self.assertIn('delete', rv.data)
        self.client.post(url_for('person_delete', pk=person.id))
        self._del_all_instance(Person)

    def test_person_normal_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_normal_reg', pk=person.id))
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.assertTrue(person.can_retire)
        self._del_all_instance(Person)

    def test_person_retire_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.client.post(url_for('person_retire_reg', pk=person.id), data={
            'date': '2011-08-01'})
        person = self.session.query(Person).get(person.id)
        self.assertEqual(date(2011, 8, 1), person.retire_day)
        self._del_all_instance(Person)

    def test_person_batch_normal(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        map(lambda x: self._add_person(
            '4205251951070100{:0>2}'.format(x),
            '1951-07-{:0>2}'.format(x), 'test{}'.format(x),
            self.parent_addr.id), range(1, 10))
        self.assertGreaterEqual(Person.query.filter(
            Person.idcard.like('420525195107%')).all(), 9)
        self.assertIn('420525195107',
                      [p.idcard[:12] for p in self.session.query(
                          Person).all()])
        self.client.post(url_for('person_batch_normal'), data=dict(
            start_date='1951-07-01', end_date='1951-07-31'))
        for person in self.session.query(Person).filter(
                Person.idcard.like('420525195107%')).all():
            person = self.session.query(Person).get(person.id)
            self.assertTrue(person.can_retire)
        self._del_all_instance(Person)

    def test_person_dead_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(url_for('person_dead_reg', pk=person.id),
                              data=dict(date='2015-07-01'))
        self.assert500(rv)
        person = self.session.query(Person).get(person.id)
        self.assertFalse(person.can_retire)
        self.client.post(url_for('person_normal_reg', pk=person.id))
        person = self.session.query(Person).get(person.id)
        self.assertTrue(person.can_retire)
        self.client.post(url_for('person_dead_reg', pk=person.id),
                         data=dict(date='2015-07-01'))
        person = self.session.query(Person).get(person.id)
        self.assertEqual(person.dead_day, date(2015, 7, 1))
        self._del_all_instance(Person)
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.client.post(url_for('person_retire_reg', pk=person.id),
                         data=dict(date='2011-08-01'))
        person = self.session.query(Person).get(person.id)
        self.assertTrue(person.can_dead_retire)
        self.client.post(url_for('person_dead_reg', pk=person.id),
                         data=dict(date='2015-07-01'))
        person = self.session.query(Person).get(person.id)
        self.assertEqual(person.dead_day, date(2015, 7, 1))
        self._del_all_instance(Person)

    def test_person_abort_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(url_for('person_abort_reg', pk=person.id))
        self.assert500(rv)
        rv = self.client.post(url_for('person_normal_reg', pk=person.id))
        self.assert200(rv)
        rv = self.client.post(url_for('person_abort_reg', pk=person.id))
        self.assert200(rv)
        person = self.session.query(Person).get(person.id)
        self.assertFalse(person.can_retire)
        self.assertFalse(person.can_normal)
        self._del_all_instance(Person)

    def test_person_suspend_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
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
        person = self.session.query(Person).get(person.id)
        self.assertTrue(person.can_resume)
        self.client.post(url_for('admin_user_remove_role', pk=self.admin.id),
                         data=dict(role=role.id))
        self.admin.roles = filter(lambda r: r.id != role.id, self.admin.roles)
        self.session.commit()
        self.session.delete(role)
        self.session.commit()
        self._del_all_instance(Person)

    def test_person_resume_reg(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(Person)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
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
        person = self.session.query(Person).get(person.id)
        self.assertTrue(person.can_suspend)
        self.client.post(url_for('admin_user_remove_role', pk=self.admin.id),
                         data=dict(role=role.id))
        self.client.post(url_for('admin_role_remove', pk=role.id))
        self._del_all_instance(Person)

    def test_person_update(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self._del_all_instance(OperationLog)
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = self.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('person_update', pk=person.id), data=dict(
            idcard='420525195107020011',
            name='test2',
            address_detail='no.1',
            securi_no='14124',
            personal_wage='11.94',
            address_id=self.parent_addr.id,
            birthday='1951-07-02'))
        person = self.session.query(Person).get(person.id)
        self.assertEqual('420525195107020011', person.idcard)
        self.assertEqual(date(1951, 7, 2), person.birthday)
        rv = self.client.get(url_for('person_update', pk=person.id))
        self.assertIn('1951-07-02', rv.data)
        self._del_all_instance(Person)

    def test_person_log_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        for i in range(10):
            self._add_person(
                '4205251951070100{:0>2}'.format(i),
                '1951-07-01',
                'test',
                self.parent_addr.id)
        person = Person.query.filter(
            Person.idcard.like('4205251951070100%')).first()
        rv = self.client.get(url_for('person_log_search',
                                     pk=person.id,
                                     start_date='2015-01-01',
                                     end_date='2015-12-31',
                                     operator_id=self.admin.id,
                                     page=1,
                                     per_page=10))
        self.assert200(rv)
        self._del_all_instance(Person)
        persons = Person.query.filter(
            Person.idcard.like('4205251951070100%')).all()
        self.assertFalse(persons)
        self.client.post(url_for('admin_log_clean', operator_id=self.admin.id))
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.parent_addr.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        for i in range(10):
            self.client.post(url_for('person_update', pk=person.id),
                             data=dict(
                                 idcard='420525195107020011',
                                 name='test2',
                                 address_detail='no.1',
                                 securi_no='14124',
                                 personal_wage='11.94',
                                 address_id=self.parent_addr.id,
                                 birthday='1951-07-02'))
        rv = self.client.get(url_for('person_log_search',
                                     pk=person.id,
                                     start_date='2015-01-01',
                                     end_date='2015-12-31',
                                     operator_id=self.admin.id,
                                     page=1,
                                     per_page=10))
        self.assertIn('person_update', rv.data)
        self._del_all_instance(OperationLog)
        self._del_all_instance(Person)

    def test_person_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._del_all_instance(Person)
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address.id)
        rv = self.client.get(url_for('person_search',
                                     idcard='420525',
                                     name='tes',
                                     page=1,
                                     per_page=2))
        self.assertIn('test', rv.data)
        rv = self.client.get(url_for('person_search',
                                     idcard='420525',
                                     name='tes',
                                     page=1,
                                     per_page=2))
        self.assertIn('test', rv.data)
        self._del_all_instance(Person)

    def test_standard_bind(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._del_all_instance(Person)
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.get(url_for('standard_bind', pk=person.id))
        self.assertIn('standard_id', rv.data)
        self.assertIn('start_date', rv.data)
        self.assertIn('end_date', rv.data)
        standard = Standard(name='test', money='100')
        self.session.add(standard)
        self.session.commit()

        def bind():
            return self.client.post(url_for('standard_bind', pk=person.id),
                                    data=dict(
                                        standard_id=standard.id,
                                        start_date='2011-08-01',
                                        end_date='2015-07-01'))
        rv = bind()
        self.assert500(rv)
        self.client.post(url_for('person_normal_reg', pk=person.id))
        self.client.post(
            url_for('person_retire_reg', pk=person.id),
            data={'date': '2011-08-01'})
        person = self.session.query(Person).get(person.id)
        self.assertEqual(date(2011, 8, 1), person.retire_day)
        self.assertTrue(person.is_valid_standard_wages)
        bind()
        self.assertEqual(100, person.standard_wages[0].money)
        self.session.delete(person.stand_assoces[0])
        self.session.commit()
        self._del_all_instance(Person)
        self._del_all_instance(Standard)


class StandardTestCase(TestBase):

    def setUp(self):
        super(StandardTestCase, self).setUp()
        role = Role(name='admin')
        db.session.add(role)
        self.admin.roles.append(role)
        db.session.commit()

    def test_standard_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('standard_add'))
        self.assert200(rv)
        self.client.post(url_for('standard_add'), data=dict(
            name='test1',
            money='100'))
        standard = Standard.query.filter(Standard.name == 'test1').one()
        self.assertEqual(100, standard.money)
        db.session.delete(standard)
        db.session.commit()


class BankcardTestBase(TestBase, PersonAddRemoveMixin, AddressDataMixin):
    def setUp(self):
        super(BankcardTestBase, self).setUp()
        PersonAddRemoveMixin.__init__(self)
        AddressDataMixin.__init__(self)
        role = Role(name='admin')
        db.session.add(role)
        db.session.commit()
        self.admin.roles.append(role)
        db.session.commit()
        self.addr = self.parent_addr
        db.session.commit()
        self.admin.address = self.addr
        db.session.commit()


class BankcardTestCase(BankcardTestBase):
    def test_bankcard_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('bankcard_add'))
        self.assertIn('no', rv.data)
        self.assertIn('name', rv.data)
        self.assertIn('submit', rv.data)
        self.client.post(url_for('bankcard_add'), data=dict(
            no='6228410770613888888', name='test'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.assertEqual(bankcard.name, 'test')
        db.session.delete(bankcard)
        db.session.commit()


class BankcardTestCase2(BankcardTestBase):
    def test_bankcard_bind(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('bankcard_add'), data=dict(
            no='6228410770613888888', name='test'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address.id)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id), data={
            'idcard': '420525195107010010'})
        self.assertEqual('420525195107010010', bankcard.owner.idcard)
        db.session.delete(bankcard)
        db.session.commit()
        db.session.delete(person)
        db.session.commit()


class BankcardTestCase3(BankcardTestBase):
    def test_bankcard_update(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('bankcard_add'), data=dict(
            no='6228410770613888888', name='test'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_update', pk=bankcard.id),
                         data=dict(no='6228410770613888888', name='test2'))
        self.assertEqual(bankcard.name, 'test2')
        db.session.delete(bankcard)
        db.session.commit()

    def test_bankcard_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('bankcard_add'), data=dict(
            no='6228410770613888888', name='test'))
        bankcard = db.session.query(Bankcard).filter(
            Bankcard.no == '6228410770613888888').one()
        rv = self.client.get(url_for(
            'bankcard_search',
            no='622841', name='te', idcard='None', page=1, per_page=2))
        self.assertIn('test', rv.data)
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address.id)
        person = db.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id), data=dict(
            idcard='420525195107010010'))
        rv = self.client.get(url_for(
            'bankcard_search',
            no='622841', name='te', idcard='None', page=1, per_page=2))
        self.assertIn('test', rv.data)
        self.client.post(url_for('bankcard_update', pk=bankcard.id),
                         data=dict(no='6228410770613888888', name='test2'))
        self.assertEqual(bankcard.name, 'test2')
        db.session.delete(bankcard)
        db.session.commit()
        db.session.delete(person)
        db.session.commit()


class NoteTestCase(TestBase, AddressDataMixin):

    def setUp(self):
        super(NoteTestCase, self).setUp()
        AddressDataMixin.__init__(self)
        role = Role(name='admin')
        role2 = Role(name='person_admin')
        db.session.add_all([role, role2])
        db.session.commit()
        self.admin.roles.extend([role, role2])
        self.admin.address = self.parent_addr
        db.session.commit()

    def test(self):
        from forms import NoteForm
        from models import Note
        formdata = MultiDict([
            ('content', 'sdfsafasdf'),
            ('start_date', self.tomorrow_str),
            ('end_date', self._days_tomorrow_str(self.tomorrow))])
        form = NoteForm(formdata=formdata)
        self.assertTrue(form.validate())
        note = Note()
        form.populate_obj(note)
        self.assertEqual(self.tomorrow, note.start_date)
        self.assertEqual(self._days_tomorrow(self.tomorrow), note.end_date)
        formdata = MultiDict([
            ('content', 'sdfsafasdf'),
            ('start_date', self.tomorrow_str)])
        form = NoteForm(formdata=formdata)
        form.populate_obj(note)
        self.assertTrue(form.validate())
        self.assertEqual(self.tomorrow, note.start_date)
        self.assertIsNone(note.end_date)

    def test_note_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post('/')
        db.session.query(Note).delete()
        db.session.commit()
        self.client.get(url_for('note_add'))
        self.client.post(url_for('note_add'), data=dict(
            content='xxxyyy',
            start_date=self.tomorrow_str))
        note = db.session.query(Note).filter(Note.content == 'xxxyyy').one()
        self.assertIsNotNone(note)
        self.assertEqual(note.start_date, self.tomorrow)
        db.session.delete(note)
        db.session.delete(note)
        self.client.post(url_for('note_add'), data=dict(
            content='xxxyyy',
            start_date=self.tomorrow_str,
            end_date=self._days_tomorrow_str(self.tomorrow)))
        note = db.session.query(Note).filter(Note.content == 'xxxyyy').one()
        self.assertFalse(note.effective)
        self.assertEqual(self._days_tomorrow(self.tomorrow), note.end_date)
        db.session.delete(note)
        db.session.commit()

    def test_note_add_to_person(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        db.session.query(Person).delete()
        db.session.commit()
        db.session.add_all(_create_persons(
            '42052519510701', 1, self.parent_addr, self.admin))
        db.session.commit()
        person = db.session.query(Person).filter(
            Person.idcard == '420525195107010001').one()
        rv = self.client.get(url_for('note_add_to_person', pk=person.id))
        self.assert200(rv)
        rv = self.client.post(url_for('note_add_to_person', pk=person.id),
                              data=dict(
                                  content='xxxyyy',
                                  start_date=self.today_str,
                                  end_date=self._days_tomorrow_str(
                                      self.tomorrow)))
        rv = self.client.get(url_for('admin_log_search',
                                     operator_id=self.admin.id,
                                     start_date=self.today_str,
                                     end_date=self.tomorrow_str,
                                     page='1',
                                     per_page='19'))
        self.assertIn('note_add_to_person', rv.data)
        self.assert200(rv)
        self.assertEqual('xxxyyy', person.notes[0].content)
        db.session.query(Note).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_note_finish(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('note_add'), data=dict(
            content='xxxyyy',
            start_date=self.today_str,
            end_date=self._days_tomorrow_str(self.tomorrow)))
        note = db.session.query(Note).filter(Note.content == 'xxxyyy').one()
        self.assertFalse(note.finished)
        rv = self.client.get(url_for('note_finish', pk=10000))
        self.assert404(rv)
        rv = self.client.post(url_for('note_finish', pk=100000))
        self.assert404(rv)
        rv = self.client.get(url_for('note_finish', pk=note.id))
        self.assert200(rv)
        self.client.post(url_for('note_finish', pk=note.id))
        self.assertTrue(note.finished)
        self.assertEqual(note.end_date, self.tomorrow)
        db.session.delete(note)
        db.session.commit()

    def test_note_disable(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('note_add'), data=dict(
            content='xxxyyy',
            start_date=self.today_str,
            end_date=self._days_tomorrow_str(self.tomorrow)))
        note = db.session.query(Note).filter(Note.content == 'xxxyyy').one()
        self.assertTrue(note.effective)
        self.assertFalse(note.finished)
        rv = self.client.get(url_for('note_disable', pk=10000))
        self.assert404(rv)
        rv = self.client.post(url_for('note_disable', pk=100000))
        self.assert404(rv)
        rv = self.client.get(url_for('note_disable', pk=note.id))
        self.assert200(rv)
        self.client.post(url_for('note_disable', pk=note.id))
        self.assertFalse(note.effective)
        self.assertFalse(note.finished)
        db.session.delete(note)
        db.session.commit()

    def test_note_clean(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('note_add'), data=dict(
            content='xxxyyy',
            start_date=self.yestoday_str))
        notes = db.session.query(Note).filter(Note.content == 'xxxyyy').all()
        self.assertTrue(notes)
        rv = self.client.post(url_for('note_clean'), data=dict(
            date=self.today_str))
        self.assert200(rv)
        notes = db.session.query(Note).filter(Note.content == 'xxxyyy').all()
        self.assertFalse(notes)

    def test_note_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('note_add'), data=dict(
            content='xxxyyy',
            start_date=self.yestoday,
            end_date=self.tomorrow_str))
        rv = self.client.get(url_for('note_search', finished=True, page=1,
                                     per_page=10))
        self.assertIn('xxxyyy', rv.data)
        rv = self.client.get(url_for('note_search', finished=False, page=1,
                                     per_page=10))
        self.assertNotIn('xxxyyy', rv.data)
        self.client.post(url_for('note_add'), data=dict(
            content='yyyzzz',
            start_date=self.yestoday,
            end_date=self._days_tomorrow_str(self.tomorrow)))
        rv = self.client.get(url_for('note_search', finished=True, page=1,
                                     per_page=10))
        self.assertNotIn('yyyzzz', rv.data)
        rv = self.client.get(url_for('note_search', finished=False, page=1,
                                     per_page=10))
        self.assertIn('yyyzzz', rv.data)
        db.session.query(Note).delete()
        db.session.commit()

    def test_note_to_user(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self.client.post(url_for('admin_add_user'), data=dict(
            name='test', password='test'))
        user = db.session.query(User).filter(User.name == 'test').one()
        self.assertEqual(User(name='test', password='test'), user)
        self.assertEqual(User(name='test', password='test'), user)
        self.client.post(url_for('note_to_user', user_id=user.id), data=dict(
            content='xxxyyy',
            start_date=self.yestoday,
            end_date=self._days_tomorrow_str(self.tomorrow)))
        rv = self.client.get(url_for('note_search', finished=False, page=1,
                                     per_page=10))
        self.assertIn('xxxyyy', rv.data)
        note = db.session.query(Note).filter(Note.content == 'xxxyyy').one()
        self.assertEqual(self.yestoday, note.start_date)
        self.assertEqual(note.user, user)
        db.session.query(Note).delete()
        db.session.commit()
        db.session.delete(user)
        db.session.commit()


class PayItemTestCase(TestBase):
    def setUp(self):
        super(PayItemTestCase, self).setUp()
        role = Role(name='pay_admin')
        db.session.add(role)
        db.session.commit()
        self.admin.roles.append(role)
        db.session.commit()

    def test_payitem_add(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.get(url_for('payitem_add'))
        self.assertIn('parent_id', rv.data)
        self.client.post(url_for('payitem_add'), data=dict(
            name='sys',
            direct=1))
        self.client.get('/')
        item = db.session.query(
            PayBookItem).filter(PayBookItem.name == 'sys').one()
        self.assertEqual(1, item.direct)
        db.session.delete(item)
        db.session.commit()

    def test_payitem_detail(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('payitem_add'), data=dict(
            name='sys', direct=1))
        self.client.get('/')
        item = db.session.query(PayBookItem).filter(
            PayBookItem.name == 'sys').one()
        rv = self.client.get(url_for('pay_item_detail', pk=item.id))
        self.assertIn('sys', rv.data)
        self.client.post(url_for('payitem_add'), data=dict(
            name='child', direct=1, parent_id=item.id))
        rv = self.client.get(url_for('pay_item_detail', pk=item.id))
        self.assertIn('child', rv.data)
        db.session.query(PayBookItem).filter(
            PayBookItem.name == 'child').delete()
        db.session.commit()
        db.session.delete(item)
        db.session.commit()


class PayBookTestCase(TestBase, AddressDataMixin, PersonAddRemoveMixin):
    def setUp(self):
        super(PayBookTestCase, self).setUp()
        AddressDataMixin.__init__(self)
        PersonAddRemoveMixin.__init__(self)
        sys, sys_amend, sys_should = (
            PayBookItem(name='sys', direct=1),
            PayBookItem(name='sys_should_pay', direct=1),
            PayBookItem(name='sys_amend', direct=1))
        bank, bank_should, bank_payed, bank_failed = (
            PayBookItem(name='bank', direct=1),
            PayBookItem(name='bank_should_pay', direct=1),
            PayBookItem(name='bank_payed', direct=1),
            PayBookItem(name='bank_failed', direct=1))
        db.session.add_all(
            [sys, sys_amend, sys_should, bank, bank_should, bank_payed,
             bank_failed])
        db.session.commit()
        sys.childs.extend([sys_amend, sys_should])
        bank.childs.extend([bank_should, bank_payed, bank_failed])
        db.session.commit()
        roles = [Role(name=name) for name in
                 ('person_admin', 'pay_admin', 'admin')]
        db.session.add_all(roles)
        db.session.commit()
        self.admin.roles.extend(roles)
        self.admin.address = self.parent_addr
        db.session.commit()

    def _sum(self, books, item=None):
        if item is not None:
            books = filter(lambda b: b.item_is(item), books)
        return sum(map(lambda b: b.money, books))

    def test_paybook_upload(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        rv = self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010010',
            name='test',
            birthday='1951-07-01',
            address_id=self.parent_addr.id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))
        self.assert200(rv)
        person = db.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        csvstr = r'xx|test|420525195107010010|60|xx|6228410770613888888'
        rv = self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                              data=dict(file=(io.BytesIO(csvstr), 'test.csv')))
        self.assert500(rv)
        bankcard = db.session.query(Bankcard).filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id),
                         data=dict(idcard='420525195107010010'))
        rv = self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                              data=dict(file=(io.BytesIO(csvstr), 'test.csv')))
        self.assertEqual(2, len(person.paybooks))
        db.session.query(PayBook).delete()
        db.session.commit()
        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010011',
            name='test',
            birthday='1951-07-01',
            address_id=self.parent_addr.id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))
        csvstr += '\nxx|test|420525195107010011|60|xx|6228410770613888888'
        person2 = db.session.query(Person).filter(
            Person.idcard == '420525195107010011').one()
        rv = self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                              data=dict(file=(io.BytesIO(csvstr), 'test.csv')))
        self.assertEqual(2, len(person2.paybooks))
        self.assertEqual(2, len(person.paybooks))
        self.assertEqual(1, len(filter(
            lambda e: e.item.name == 'bank_should_pay', person2.paybooks)))
        self.assertEqual(
            60.0,
            sum(map(lambda e: e.money,
                    filter(
                        lambda e: e.item.name == 'bank_should_pay',
                        person2.paybooks))))
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete(synchronize_session=False)
        db.session.commit()

    def test_paybook_amend(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010010',
            name='test',
            birthday='1951-07-01',
            address_id=self.parent_addr.id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        bankcard = db.session.query(Bankcard).filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id),
                         data=dict(idcard='420525195107010010'))
        csvstr = r'xx|test|420525195107010010|60|xx|6228410770613888888'
        self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                         data=dict(file=(io.BytesIO(csvstr), 'test.csv')))
        self.assertEqual(60.0, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test2', no='6228410770613666666'))
        bankcard2 = Bankcard.query.filter(
            Bankcard.no == '6228410770613666666').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard2.id),
                         data=dict(idcard='420525195107010010'))
        person = db.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        rv = self.client.post(
            url_for(
                'paybook_amend',
                person_id=person.id,
                peroid='2011-8-1'),
            data=dict(
                bankcard='6228410770613666666',
                money='75.00'))
        self.assert200(rv)
        self.assertEqual(0.00, self._sum(bankcard.paybooks, 'sys_should_pay'))
        self.assertEqual(0.00, self._sum(bankcard.paybooks, 'bank_should_pay'))
        # =================================================
        self.assertEqual(-75.00, self._sum(bankcard2.paybooks,
                                           'sys_amend'))
        self.assertEqual(0.00, self._sum(bankcard2.paybooks, 'sys_should_pay'))
        self.assertEqual(75.00,
                         self._sum(bankcard2.paybooks, 'bank_should_pay'))
        self.assertEqual(0.00, sum(map(lambda b: b.money, bankcard2.paybooks)))
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.assertEqual(0.00, sum(map(lambda e: e.money, person.paybooks)))
        person_sys_books = filter(lambda e: e.item.name == 'sys_should_pay',
                                  person.paybooks)
        self.assertEqual(0.00, sum(map(lambda e: e.money, person_sys_books)))
        person_bank_books = filter(lambda e: e.item.name == 'bank_should_pay',
                                   person.paybooks)
        self.assertEqual(75.00, sum(map(lambda e: e.money, person_bank_books)))
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_paybook_batch_success(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010010',
            name='test',
            birthday='1951-07-01',
            address_id=self.parent_addr.id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        bankcard1 = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard1.id),
                         data=dict(idcard='420525195107010010'))
        self.client.post(url_for('person_add'), data=dict(
            idcard='420525195107010011',
            name='test2',
            birthday='1951-07-01',
            address_id=self.parent_addr.id,
            address_detail='xxxx',
            securi_no=uuid4().hex,
            personal_wage='0.94'))
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test2', no='6228410770613666666'))
        bankcard2 = Bankcard.query.filter(
            Bankcard.no == '6228410770613666666').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard2.id), data=dict(
            idcard='420525195107010011'))
        upload_str = 'x|test|420525195107010010|60|x|6228410770613888888\n' +\
                     'x|test|420525195107010011|60|x|6228410770613666666'
        self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                         data=dict(file=(io.BytesIO(upload_str), 'test.csv')))
        self.assertEqual(60, self._sum(bankcard1.paybooks, 'bank_should_pay'))
        self.client.post(url_for('paybook_batch_success'), data=dict(
            peroid='2011-08-01', fails='6228410770613888888'))
        self.assertEqual(0, self._sum(bankcard1.paybooks, 'bank_should_pay'))
        self.assertEqual(60, self._sum(bankcard1.paybooks, 'bank_failed'))
        self.assertEqual(0, self._sum(bankcard1.paybooks, 'bank_payed'))
        self.assertEqual(0, self._sum(bankcard2.paybooks, 'bank_should_pay'))
        self.assertEqual(60, self._sum(bankcard2.paybooks, 'bank_payed'))
        self.assertEqual(0, self._sum(bankcard2.paybooks, 'bank_failed'))
        # bank should pay is 0, no change
        self.client.post(url_for('paybook_batch_success'), data=dict(
            peroid='2011-08-01', fails='6228410770613888888'))
        self.assertEqual(4, len(bankcard1.paybooks))
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_paybook_fail_correct(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address_id, db.session)
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id), data=dict(
            idcard='420525195107010010'))
        upload_str = 'x|test|420525195107010010|60|x|6228410770613888888'
        self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                         data=dict(file=(io.BytesIO(upload_str), 'test.csv')))
        self.assertEqual(60, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_payed'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_failed'))
        self.client.post(url_for('paybook_batch_success'), data=dict(
            peroid='2011-08-01', fails='6228410770613888888'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.assertEqual(60, self._sum(bankcard.paybooks, 'bank_failed'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_payed'))
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test2', no='6228410770613666666'))
        bankcard2 = Bankcard.query.filter(
            Bankcard.no == '6228410770613666666').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard2.id), data=dict(
            idcard='420525195107010010'))
        person = db.session.query(Person).filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for('paybook_fail_correct',
                                 person_id=person.id,
                                 peroid=date(2011, 8, 1)),
                         data=dict(
                             bankcard='6228410770613666666'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_failed'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.assertEqual(60, self._sum(bankcard2.paybooks, 'bank_should_pay'))
        self.assertEqual(0, self._sum(bankcard2.paybooks, 'bank_failed'))
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_paybook_success_correct(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address_id, db.session)
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id), data=dict(
            idcard='420525195107010010'))
        upload_str = 'x|test|420525195107010010|60|x|6228410770613888888'
        self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                         data=dict(file=(io.BytesIO(upload_str), 'test.csv')))
        self.assertEqual(60, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.assertEqual(0, self._sum(bankcard.paybooks))
        self.assertEqual(-60, self._sum(bankcard.paybooks, 'sys_should_pay'))
        self.client.post(url_for('paybook_batch_success'), data=dict(
            peroid='2011-08-01'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.assertEqual(60, self._sum(bankcard.paybooks, 'bank_payed'))
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(
            url_for(
                'paybook_success_correct',
                bankcard_id=bankcard.id,
                person_id=person.id,
                peroid='2011-08-01'),
            data=dict(money=30))
        self.assertEqual(30, self._sum(bankcard.paybooks, 'bank_payed'))
        self.assertEqual(0, self._sum(bankcard.paybooks, 'bank_should_pay'))
        self.assertEqual(30, self._sum(bankcard.paybooks, 'bank_failed'))
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_paybook_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._add_person(
            '420525195107010010', '1951-07-01', 'test', self.admin.address_id,
            db.session)
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id),
                         data=dict(idcard='420525195107010010'))
        upload_str = 'x|test|420525195107010010|60|x|6228410770613888888'
        self.client.post(
            url_for('paybook_upload', peroid='2011-8-1'),
            data=dict(file=(io.BytesIO(upload_str), 'test.csv')))
        self.client.post(url_for('paybook_batch_success'), data=dict(
            peroid=date(2011, 8, 1)))
        self.assertEqual(60, self._sum(bankcard.paybooks, 'bank_payed'))
        rv = self.client.get(url_for('paybook_search', page=1, per_page=2))
        self.assertIn('6228410770613888888', rv.data)
        rv = self.client.get(url_for(
            'paybook_search',
            page=1,
            per_page=1,
            all='yes'))
        self.assertIn('6228410770613888888', rv.data)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(
            url_for(
                'paybook_success_correct',
                person_id=person.id,
                bankcard_id=bankcard.id,
                peroid=date(2011, 8, 1)),
            data=dict(money=30))
        self.assertEqual(30, self._sum(bankcard.paybooks, 'bank_payed'))
        self.assertEqual(30, self._sum(bankcard.paybooks, 'bank_failed'))
        rv = self.client.get(
            url_for(
                'paybook_search',
                page=1,
                per_page=1,
                all='yes'))
        self.assertIn('420525195107010010', rv.data)
        self.assertNotIn('sys_should_pay', rv.data)
        self.assertNotIn('sys_amend', rv.data)
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_paybook_sys_search(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address_id, db.session)
        self.client.post(url_for('bankcard_add'), data=dict(
            name='test', no='6228410770613888888'))
        bankcard = Bankcard.query.filter(
            Bankcard.no == '6228410770613888888').one()
        self.client.post(url_for('bankcard_bind', pk=bankcard.id),
                         data=dict(idcard='420525195107010010'))
        upload_str = 'x|test|420525195107010010|60|x|6228410770613888888'
        self.client.post(url_for('paybook_upload', peroid='2011-8-1'),
                         data=dict(file=(io.BytesIO(upload_str), 'test.csv')))
        self.assertEqual(-60, self._sum(bankcard.paybooks, 'sys_should_pay'))
        rv = self.client.get(url_for(
            'paybook_sys_search',
            page=1, per_page=2))
        self.assertIn('60', rv.data)
        self.assertIn('sys_should_pay', rv.data)
        self.assertNotIn('sys_amend', rv.data)
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.client.post(url_for(
            'paybook_amend',
            person_id=person.id,
            peroid='2011-8-1'),
            data=dict(
                bankcard='6228410770613888888',
                money='75.00'))
        rv = self.client.get(url_for(
            'paybook_sys_search',
            page=1, per_page=2))
        self.assertNotIn('75', rv.data)
        self.assertNotIn('sys_should_pay', rv.data)
        self.assertNotIn('sys_amend', rv.data)
        rv = self.client.get(url_for(
            'paybook_sys_search',
            all='yes', page=1, per_page=2))
        self.assertIn('75', rv.data)
        self.assertIn('sys_amend', rv.data)
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()

    def test_paybook_bankgrant(self):
        self.client.post('/login', data=dict(name='admin', password='admin'))
        self.client.get('/')
        self._add_person('420525195107010010', '1951-07-01', 'test',
                         self.admin.address_id, db.session)
        for i in range(10):
            self.client.post(url_for('bankcard_add'), data=dict(
                name='test', no='622841077061388888{}'.format(i)))
        bankcards = map(
            lambda i: Bankcard.query.filter(
                Bankcard.no == '622841077061388888{}'.format(i)).one(),
            range(10))
        for bankcard in bankcards:
            self.client.post(url_for('bankcard_bind', pk=bankcard.id),
                             data=dict(idcard='420525195107010010'))
        upload_str = ('x|test|420525195107010010|60|x|6228410770613888880\n' +
                      'x|test|420525195107010010|60|x|6228410770613888881\n' +
                      'x|test|420525195107010010|60|x|6228410770613888882\n' +
                      'x|test|420525195107010010|60|x|6228410770613888883\n' +
                      'x|test|420525195107010010|60|x|6228410770613888884\n' +
                      'x|test|420525195107010010|60|x|6228410770613888885\n' +
                      'x|test|420525195107010010|60|x|6228410770613888886\n' +
                      'x|test|420525195107010010|60|x|6228410770613888887\n' +
                      'x|test|420525195107010010|60|x|6228410770613888888\n' +
                      'x|test|420525195107010010|60|x|6228410770613888889')
        self.client.post(url_for('paybook_upload', peroid='2015-1-1'),
                         data=dict(file=(io.BytesIO(upload_str), 'test.csv')))
        person = Person.query.filter(
            Person.idcard == '420525195107010010').one()
        self.assertEqual(-600, self._sum(person.paybooks, 'sys_should_pay'))
        self.assertEqual(600, self._sum(person.paybooks, 'bank_should_pay'))
        rv = self.client.get(url_for('paybook_bankgrant',
                                     peroid=date(2015, 1, 1)))
        self.assert200(rv)
        self.assertIn('6228410770613888888', rv.data)
        db.session.query(PayBook).delete()
        db.session.commit()
        db.session.query(Bankcard).delete()
        db.session.commit()
        db.session.query(Person).delete()
        db.session.commit()


def run_test():
    db.create_all()
    unittest.main()
