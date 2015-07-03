# coding=utf-8

import datetime
from datetime import timedelta
import calendar
from hashlib import md5
from dateutil.relativedelta import relativedelta
from flask import Flask, abort
from jinja2 import Template
from sqlalchemy import or_, and_, false, exists, select, func
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask_sqlalchemy import SQLAlchemy, Pagination

app = Flask(__name__)
db = SQLAlchemy(app)

_IMPLEMENT_DATE = datetime.date(2011, 7, 1)
_MIN_ENGAGE_IN_AGE = 16


class UserRoleAssoc(db.Model):
    __tablename__ = 'users_roles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref='assoc')
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    role = db.relationship('Role', backref='assoc')

    def __repr__(self):
        return "<UserRoleAssoc(user_id={user},role_id={role})>".format(
            user=self.user_id, role=self.role_id)

    def __str__(self):
        return "{user},{role}".decode('utf-8').format(
            user=self.user.name, role=self.role.name).encode('utf-8')


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    _password = db.Column(db.String, nullable=False)
    roles = db.relationship(
        'Role',
        secondary=UserRoleAssoc.__tablename__,
        backref='users'
    )
    active = db.Column(db.Boolean, nullable=False, default=True)
    address_id = db.Column(db.Integer, db.ForeignKey('addresses.id'))
    address = db.relationship('Address', backref='users')

    def __repr__(self):
        return "<User(name='{name}',_password='{password}',active={active}\
        address_id={address})>".format(
            name=self.name,
            password=self.password,
            active=self.active,
            address=self.address_id)

    def __str__(self):
        return "{}".decode('utf-8').format(self.name).encode('utf-8')

    def is_active(self):
        return self.active

    def get_id(self):
        return unicode('{}'.format(self.id))

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def __eq__(self, other):
        if other is None:
            return False
        return self.name == other.name and self.password == other.password

    def __ne__(self, other):
        return not self.__eq__(other)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, val):
        self._password = md5(val).hexdigest()

    @password.expression
    def password(cls):
        return cls._password.label('password')

    @hybrid_method
    def has_role(self, rolename):
        return rolename in [role.name for role in self.roles]

    @has_role.expression
    def has_role(cls, rolename):
        return exists().where(
            cls.role_id == Role.id,
            Role.name == rolename)


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)

    def __eq__(self, other):
        return other and other.id == self.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "<Role(name='name')>".format(self.name)

    def __str__(self):
        return "{}".decode('utf-8').format(self.name).encode('utf-8')


class Address(db.Model):
    __tablename__ = 'addresses'
    id = db.Column(db.Integer, primary_key=True)
    no = db.Column(db.String(length=11), unique=True, nullable=False)
    name = db.Column(db.String, unique=True, nullable=False)
    parent_id = db.Column(db.Integer,
                          db.ForeignKey('addresses.id', ondelete='CASCADE'))
    parent = db.relationship('Address', cascade='all, delete-orphan',
                             backref='childs', remote_side=[id],
                             single_parent=True)

    def __eq__(self, other):
        return other and other.id == self.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "<Address(name='{name}',parent_id={parent},no='{no}')>".format(
            name=self.name.encode('utf-8'),
            parent=self.parent_id,
            no=self.no
        )

    def __str__(self):
        return "{name}".decode('utf-8').format(name=self.name).encode('utf-8')

    @property
    def descendants(self):
        descendants = []

        def append_descendants(address):
            if address.childs:
                for child in address.childs:
                    descendants.append(child)
                    append_descendants(child)
            return descendants
        return append_descendants(self)

    @hybrid_method
    def descendant_of(self, address):
        return address and self in address.descendants

    @descendant_of.expression
    def descendant_of(cls, address):
        if not address or not address.descendants:
            return false()
        return cls.id.in_(map(
            lambda addr: addr.id,
            address.descendants))

    @property
    def ancestors(self):
        ancestors = []
        parent = self.parent
        while parent:
            ancestors.append(parent)
            parent = parent.parent
        return ancestors

    @hybrid_method
    def ancestor_of(self, address):
        return address and self in address.ancestors

    @ancestor_of.expression
    def ancestor_of(cls, address):
        if not address or not address.ancestors:
            return false()
        return cls.id.in_(map(
            lambda addr: addr.id,
            address.ancestors))


class PersonStandardAssoc(db.Model):
    __tablename__ = 'person_standard'
    id = db.Column('id', db.Integer, primary_key=True)
    person_id = db.Column(
        'person_id',
        db.Integer,
        db.ForeignKey('persons.id')
    )
    person = db.relationship('Person', backref='standard_assoces')
    standard_id = db.Column(
        'standard_id',
        db.Integer,
        db.ForeignKey('standards.id')
    )
    standard = db.relationship('Standard', backref='person_assoces')
    _start_date = db.Column('start_date', db.Date, nullable=False)
    _end_date = db.Column('end_date', db.Date)

    def __repr__(self):
        return "<PersonStandardAssoc(standard_id={standard},person_id={person},\
        _start_date={start_date},_end_date={end_date})>".format(
            standard=self.standard_id,
            person=self.person_id,
            start_date=self.start_date,
            end_date=self.end_date
        )

    def __str__(self):
        return "{person},{standard},{start_date},{end_date}".decode(
            'utf-8').format(
                person=self.person.name,
                standard=self.standard.name,
                start_date=self.start_date,
                end_date=self.end_date if self.end_date else '').encode(
                    'utf-8')

    @hybrid_property
    def start_date(self):
        return self._start_date

    @start_date.expression
    def start_date(cls):
        return cls._start_date.label('start_date')

    @start_date.setter
    def start_date(self, val):
        if self.end_date is not None and val > self.end_date:
            raise DateError("start date can't later than end date")
        self._start_date = val

    @hybrid_property
    def end_date(self):
        return self._end_date

    @end_date.expression
    def end_date(self):
        return self._end_date.label('end_date')

    @end_date.setter
    def end_date(self, val):
        if self.start_date is not None and val < self.start_date:
            raise DateError("end date can't earler than start date")
        self._end_date = val

    @hybrid_method
    def effective_before(self, last_date):
        return (self.end_date is None or self.end_date >= last_date) and\
            self.start_date <= last_date

    @effective_before.expression
    def effective_before(cls, last_date):
        return and_(
            or_(
                cls.end_date.is_(None),
                cls.end_date >= last_date),
            cls.start_date <= last_date)

    @hybrid_property
    def effective(self):
        return self.effective_before(datetime.datetime.now().date())

    @effective.expression
    def effective(cls):
        return cls.effective_before(datetime.datetime.now().date())

    @hybrid_method
    def total_standard(self, person, peroid):
        money = 0.0
        for assoc in person.standard_assoces:
            if assoc.effective_before(peroid):
                money += assoc.standard.money
        return money

    @total_standard.expression
    def total_standard(cls, person, peroid):
        return select([func.sum(Standard.money).label('money')]).where(
            exists().where(and_(
                Standard.id == cls.standard_id,
                exists().where(and_(
                    cls.person_id == person.id,
                    cls.effective_before(peroid)))))).c.money


class DateError(RuntimeError):
    pass


class Person(db.Model):
    __tablename__ = 'persons'
    id = db.Column(db.Integer, primary_key=True)
    idcard = db.Column(db.String(length=18), unique=True, nullable=False)
    _birthday = db.Column(db.Date, nullable=False)
    name = db.Column(db.String, nullable=False)
    address_id = db.Column(db.Integer, db.ForeignKey('addresses.id'),
                           nullable=False)
    address = db.relationship('Address', backref=db.backref('persons',
                                                            order_by=id))
    address_detail = db.Column(db.String, nullable=False)
    securi_no = db.Column(db.String, nullable=False, unique=True)
    _personal_wage = db.Column(db.Float(precision=2), nullable=False,
                               default=0.0)
    standard_wages = db.relationship(
        'Standard',
        secondary=PersonStandardAssoc.__tablename__,
        backref='persons',
        remote_side=[id]
    )
    STATUS_CHOICES = (
        (unicode('normal-unretire'), ('正常参保')),
        (unicode('dead-unretire'), ('在职死亡')),
        (unicode('abort-unretire'), ('在职终止')),
        (unicode('normal-retire'), ('退休')),
        (unicode('abort_retire'), ('退休终止')),
        (unicode('dead-retire'), ('退休死亡')),
        (unicode('suspend-retire'), ('退休暂停')),
        (unicode('registed'), ('登记'))
    )
    (NORMAL, DEAD_UNRETIRE, ABROT_UNRETIRE, NORMAL_RETIRE, ABORT_RETIRE,
     DEAD_RETIRE, SUSPEND_RETIRE, REG) = range(len(STATUS_CHOICES))
    _status = db.Column(
        db.String, nullable=False)
    retire_day = db.Column(db.Date)
    dead_day = db.Column(db.Date)
    create_user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    create_by = db.relationship('User', backref='created_persons')
    create_time = db.Column(db.DateTime, nullable=False,
                            default=datetime.datetime.now)

    def __repr__(self):
        return "<Person(idcard='{idcard};,name='{name}',address_id={address},\
        address_detail='{address_detail}',securi_no='{securi_no}',\
        create_time={create_time},status='{status}'\
        ,birthday={birthday})>".format(
            idcard=self.idcard,
            name=self.name.encode('utf-8'),
            address=self.address_id,
            address_detail=self.address_detail.encode('utf-8'),
            securi_no=self.securi_no,
            create_time=self.create_time,
            status=self.status,
            birthday=self.birthday)

    def __str__(self):
        return '{idcard},{name},{status}'.decode('utf-8').format(
            idcard=self.idcard,
            name=self.name,
            status=self.status).encode('utf-8')

    @hybrid_property
    def personal_wage(self):
        return self._personal_wage

    @personal_wage.setter
    def personal_wage(self, val):
        if self.status != self.__status_str(self.NORMAL_RETIRE):
            self._personal_wage = 0.0
        else:
            self._personal_wage = val

    @personal_wage.expression
    def personal_wage(cls):
        return cls._personal_wage.label('personal_wage')

    @hybrid_property
    def birthday(self):
        return self._birthday

    @birthday.expression
    def birthday(cls):
        return cls._birthday.label('birthday')

    @birthday.setter
    def birthday(self, val):
        if isinstance(val, str):
            self._birthday = datetime.datetime.strptime(val, '%Y-%m-%d').date()
        else:
            self._birthday = val

    @property
    def earliest_retire_day(self):
        delta = relativedelta(years=60, months=1)
        retire_day = datetime.date(
            self.birthday.year, self.birthday.month, 1) + delta
        return max(retire_day, _IMPLEMENT_DATE)

    @classmethod
    def __status_str(cls, index):
        return cls.STATUS_CHOICES[index][0]

    @hybrid_method
    def __status_in(self, *args):
        return self.status in (self.__status_str(i) for i in args)

    @__status_in.expression
    def __status_in(cls, *args):
        return cls._status.in_(map(lambda i: cls.__status_str(i), args))

    @hybrid_method
    def __status_is(self, index):
        return self.status == self.__status_str(index)

    @__status_is.expression
    def __status_is(cls, index):
        return cls._status == cls.__status_str(index)

    def reg(self):
        if not self.can_reg:
            raise PersonStatusError(
                unicode('status error, person already been registed'))
        self._status = self.__status_str(self.REG)
        return self

    def retire(self, retire_day):
        if not self.can_retire:
            raise PersonStatusError(
                unicode('status error, person can not retire'))
        if not retire_day:
            retire_day = self.earliest_retire_day
        elif retire_day < self.earliest_retire_day:
            raise PersonAgeError('person is not reach retire day')
        self.retire_day = max(retire_day, self.earliest_retire_day)
        self._status = self.__status_str(self.NORMAL_RETIRE)
        return self

    def dead(self, dead_day):
        if self.can_dead_unretire:
            self._status = self.__status_str(self.DEAD_UNRETIRE)
        elif self.can_dead_retire:
            self._status = self.__status_str(self.DEAD_RETIRE)
            self.standard_assoces = filter(  # remove invalid standard
                lambda assoc: assoc.start_date <= dead_day,
                self.standard_assoces)
            for assoc in self.standard_assoces:
                assoc.end_date = dead_day
        else:
            raise PersonStatusError('person can not be dead')
        self.dead_day = dead_day
        return self

    def abort(self, abort_date=None):
        if self.can_abort_normal:
            self._status = self.__status_str(self.ABROT_UNRETIRE)
        elif self.can_abort_retire:
            self._status = self.__status_str(self.ABORT_RETIRE)
            self.standard_assoces = filter(  # remove invalid standard
                lambda assoc: assoc.start_date <= abort_date,
                self.standard_assoces)
            for assoc in self.standard_assoces:
                now = datetime.datetime.now().date()
                assoc.end_date = abort_date or now
        else:
            raise PersonStatusError('Person can not be abort')
        return self

    def normal(self):
        if self.can_normal:
            self._status = self.__status_str(self.NORMAL)
        else:
            raise PersonStatusError('Person can not be normal')
        return self

    def suspend(self):
        if not self.can_suspend:
            self._status = self.__status_str(self.SUSPEND_RETIRE)
        else:
            raise PersonStatusError('Person can not be suspend')
        return self

    def resume(self):
        if not self.can_resume:
            self._status = self.__status_str(self.NORMAL_RETIRE)
        else:
            raise PersonStatusError('Person can not be resume')
        return self

    @hybrid_property
    def status(self):
        return self._status

    @status.expression
    def status(cls):
        return cls._status.label('status')

    @hybrid_property
    def can_reg(self):
        if self.status is not None:
            return False
        now = datetime.datetime.now().date()
        earlist_engage_day = datetime.date(
            self.birthday.year + _MIN_ENGAGE_IN_AGE, self.birthday.month,
            self.birthday.day)
        return now > earlist_engage_day

    @can_reg.expression
    def can_reg(cls):
        now = datetime.datetime.now()
        last_date = datetime.date(
            now.year - _MIN_ENGAGE_IN_AGE, now.month, now.day)
        return and_(
            cls._status.is_(None),
            cls._birthday < last_date)

    @hybrid_property
    def can_normal(self):
        return self.__status_is(self.REG)

    @hybrid_property
    def can_abort_normal(self):
        return self.__status_is(self.NORMAL)

    @hybrid_property
    def can_abort_retire(self):
        return self.__status_in(self.NORMAL_RETIRE, self.SUSPEND_RETIRE)

    @hybrid_property
    def can_abort(self):
        return self.__status_in(self.NORMAL, self.NORMAL_RETIRE,
                                self.SUSPEND_RETIRE)

    @hybrid_property
    def can_retire(self):
        return self.__status_is(self.NORMAL)

    @hybrid_property
    def can_suspend(self):
        return self.__status_is(self.NORMAL_RETIRE)

    @hybrid_property
    def can_resume(self):
        return self.__status_in(self.SUSPEND_RETIRE)

    @hybrid_property
    def can_dead_retire(self):
        return self.__status_in(self.NORMAL_RETIRE, self.SUSPEND_RETIRE)

    @hybrid_property
    def can_dead_unretire(self):
        return self.__status_in(self.NORMAL)

    @hybrid_property
    def can_dead(self):
        return self.can_dead_retire or self.can_dead_unretire

    @can_dead.expression
    def can_dead(cls):
        return or_(cls.can_dead_retire, cls.can_dead_unretire)

    @property
    def is_valid_standard_wages(self):
        if self.status != self.__status_str(self.NORMAL_RETIRE):
            return False
        for assoc in self.standard_assoces:
            if assoc.start_date < self.retire_day:
                return False
        if not self.standard_assoces:
            return True
        standard_ids = set(map(
            lambda standard: standard.id,
            self.standard_assoces))
        for id in standard_ids:
            date_lst = map(lambda a: (a.start_date, a.end_date),
                           filter(
                               lambda standard: standard.id == id,
                               self.standard_assoces))
            date_lst.sort(key=lambda x: x[0])
            if len(date_lst) == 1:
                return True

            def f(x, y):
                START_DATE, END_DATE = 0, 1
                if x[END_DATE] is None and y[START_DATE] is not None:
                    return False
                if x[END_DATE] > y[START_DATE]:
                    return False
                return True
            if not reduce(lambda x, y: x and f(x, y), date_lst):
                return False
        return True

    @hybrid_method
    def total_wage_before(self, last_date):
        result = self.personal_wage
        for assoc in self.standard_assoces:
            if assoc.effective_before(last_date):
                result += assoc.standard.money
        return result

    @total_wage_before.expression
    def total_wage_before(cls, last_date):
        Assoc = PersonStandardAssoc
        expression = select(
            [func.sum(Standard.money).label('money')]).where(
                exists().where(and_(
                    Assoc.standard_id == Standard.id,
                    exists().where(and_(
                        Assoc.person_id == cls.id,
                        Assoc.effective_before(last_date)))))).c.money +\
            cls.personal_wage
        return expression.label('total_wage_before')

    @hybrid_property
    def total_wage(self):
        return self.total_wage_before(datetime.datetime.now().date())

    @total_wage.expression
    def total_wage(cls):
        return cls.total_wage_before(datetime.datetime.now().date())


class PersonStatusError(RuntimeError):
    ''''''


class PersonAgeError(RuntimeError):
    ''''''


class PersonStatus(object):
    ''''''


class Standard(db.Model):
    __tablename__ = 'standards'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    money = db.Column(db.Float(precision=2), nullable=False, default=0.0)

    def __repr__(self):
        return "<Standard(name='{name}', money={money})>".format(
            name=self.name.encode('utf-8'),
            money=self.money
        )

    def __str__(self):
        return '{name},{money}'.decode('utf-8').format(
            name=self.name,
            money=self.money
        ).encode('utf-8')


class Bankcard(db.Model):
    __tablename__ = 'bankcards'
    id = db.Column(db.Integer, primary_key=True)
    no = db.Column(db.String(length=19), unique=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('persons.id'))
    owner = db.relationship('Person', backref=db.backref('bankcards',
                                                         order_by=id))
    create_user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    create_by = db.relationship('User', backref='created_bankcards')
    create_time = db.Column(db.DateTime, default=datetime.datetime.now)

    def __repr__(self):
        return "<Bankcard(no='{no}',name='{name}',owner_id={owner})>".format(
            no=self.no.encode('utf-8'),
            name=self.name.encode('utf-8'),
            owner=self.owner_id)

    def __str__(self):
        return '{no}({name})'.decode('utf-8').format(
            no=self.no,
            name=self.name).encode('utf-8')

    @hybrid_property
    def binded(self):
        return self.owner is not None

    @binded.expression
    def binded(cls):
        return cls.owner.isnot(None)


class PayBookItem(db.Model):
    __tablename__ = 'paybookitems'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    direct = db.Column(db.Integer, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('paybookitems.id'))
    parent = db.relationship(
        'PayBookItem', backref='childs', remote_side=[id])

    def __repr__(self):
        return "<PayBookItem(name='{name}',parent_id={parent})>".format(
            name=self.name.encode('utf-8'),
            parent=self.parent_id)

    def __str__(self):
        return '{name}'.decode('utf-8').format(name=self.name).encode('utf-8')

    @property
    def descendants(self):
        descendants = []

        def append_descendants(item):
            if item.childs:
                for child in item.childs:
                    descendants.append(child)
                    append_descendants(child)
            return descendants
        return append_descendants(self)

    @hybrid_method
    def descendant_of(self, item):
        return item and self in item.descendants

    @descendant_of.expression
    def descendant_of(cls, item):
        if not item or not item.descendants:
            return false()
        return cls.id.in_(map(
            lambda item: item.id,
            item.descendants))

    @property
    def ancestors(self):
        ancestors = []
        parent = self.parent
        while parent:
            ancestors.append(parent)
            parent = parent.parent
        return ancestors

    @hybrid_method
    def ancestor_of(self, item):
        return item and self in item.ancestors
    
    @ancestor_of.expression
    def ancestor_of(cls, item):
        if not item or not item.ancestors:
            return false()
        return cls.id.in_(map(
            lambda item: item.id,
            item.ancestors))


class FormatError(RuntimeError):
    ''''''


class PayBook(db.Model):
    __tablename__ = 'paybooks'
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('persons.id'),
                          nullable=False)
    person = db.relationship('Person', backref='paybooks')
    bankcard_id = db.Column(db.Integer, db.ForeignKey('bankcards.id'))
    bankcard = db.relationship('Bankcard', backref='paybooks')
    item_id = db.Column(db.Integer, db.ForeignKey('paybookitems.id'),
                        nullable=False)
    money = db.Column(db.Float(precision=2), nullable=False)
    _peroid = db.Column(db.Date, default=datetime.datetime.now,
                        nullable=False)
    _item = db.relationship('PayBookItem')
    create_date = db.Column(
        db.Date, nullable=False, default=datetime.datetime.now)
    create_user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    create_by = db.relationship('User', backref='paybooks')
    remark = db.Column(db.String)

    def __repr__(self):
        return "<PayBook(money='{money}',person_id={person}," +\
            "bankcard_id={bankcard},item_id={item},peroid={peroid})>".format(
                money=self.money,
                person=self.person_id,
                bankcard=self.bankcard_id,
                item=self.item_id,
                peroid=self.peroid)

    def __str__(self):
        return '{person},{bankcard},{item},{money},{peroid}'.decode(
            'utf-8').format(
                person=self.person,
                bankcard=self.bankcard,
                item=self.item,
                money=self.money,
                peroid=self.peroid).encode('utf-8')

    @hybrid_property
    def item(self):
        return self._item

    @item.expression
    def item(self):
        return self._item.label('item')

    @item.setter
    def item(self, val):
        if isinstance(val, int):
            self.item_id = val
        else:
            self._item = val

    @hybrid_property
    def peroid(self):
        return self._peroid

    @peroid.expression
    def peroid(self):
        return self._peroid.label('peroid')

    @peroid.setter
    def peroid(self, val):
        '''val's format is %Y%m, for example:201503'''
        if isinstance(val, (datetime.datetime, datetime.date)):
            self._peroid = datetime.date(val.year, val.month, 1)
        elif isinstance(val, (str,)):
            self._peroid = datetime.datetime.strptime(val, '%Y%m').date()
        else:
            self._peroid = val  # may raise exception

    @classmethod
    def _date_range(cls, peroid):
        if isinstance(peroid, str):
            peroid = datetime.datetime.strptime(peroid, '%Y%m').date()
        year, month = peroid.year, peroid.month
        first_date = datetime.date(year, month, 1)
        last_date = datetime.date(year, month, calendar.monthrange(
            year, month)[1])
        return first_date, last_date

    @hybrid_method
    def in_peroid(self, peroid):
        if peroid is None:
            return False
        m_range = self._date_range(peroid)
        return m_range[0] <= self.peroid <= m_range[1]

    @in_peroid.expression
    def in_peroid(cls, peroid):
        if peroid is None:
            return false()
        m_range = cls._date_range(peroid)
        return and_(
            cls.peroid.isnot(None),
            cls.peroid >= m_range[0],
            cls.peroid <= m_range[1])

    @hybrid_method
    def item_is(self, item_name):
        return self.item.name == item_name

    @item_is.expression
    def item_is(cls, item_name):
        return exists().where(and_(
            PayBook.item_id == PayBookItem.id,
            PayBookItem.name == item_name))

    @hybrid_method
    def item_in(self, item_names):
        return self.item.name in item_names

    @item_in.expression
    def item_in(self, item_names):
        return exists().where(and_(
            PayBookItem.id == PayBook.item_id,
            PayBookItem.name.in_(item_names))) if item_names else false()

    @classmethod
    def create_tuple(cls, person, item1, item2, bankcard1,
                     bankcard2, money, peroid, user):

        def _create_dict(item, bankcard, money):
            result = {}
            if isinstance(person, int):
                result.update(person_id=person)
            else:
                result.update(person=person)
            if isinstance(bankcard, int):
                result.update(bankcard_id=bankcard)
            else:
                result.update(bankcard=bankcard)
            if isinstance(item, int):
                result.update(item_id=item)
            else:
                result.update(item=item)
            if isinstance(user, int):
                result.update(create_user_id=user)
            else:
                result.update(create_by=user)
            result.update(money=money)
            result.update(peroid=peroid)
            return result
        return (PayBook(**_create_dict(_item, _bankcard, _money))
                for _item, _bankcard, _money in
                ((item1, bankcard1, -money), (item2, bankcard2, money)))

    def forward_tuple(self, forward_item, bankcard, user):
        return self.create_tuple(self.person, self.item, forward_item,
                                 self.bankcard, bankcard, self.money,
                                 self.peroid, user)


class OperationLog(db.Model):
    __tablename__ = 'operation_logs'
    id = db.Column(db.Integer, primary_key=True)
    operator_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    operator = db.relationship('User', backref='logs')
    method = db.Column(db.String, nullable=False)
    remark = db.Column(db.String)
    time = db.Column(
        db.DateTime, default=datetime.datetime.now, nullable=False)

    def __repr__(self):
        return "<OperationLog(operator_id={operator},method='{method}',\
        remark='{remark}',time={time})>".format(
            operator=self.operator_id,
            method=self.method,
            remark=self.remark.encode('utf-8'),
            time=self.time
        )

    def __str__(self):
        return "{operator},{method},{remark},{time}".decode('utf-8').format(
            operator=self.operator.name,
            method=self.method,
            remark=self.remark,
            time=self.time).encode('utf-8')

    __log_templates = {}

    @classmethod
    def log_template(cls, template=None, name=None):
        def decorator(f):
            cls.__log_templates[name or f.__name__]\
                = Template(template) if template else None
            return f
        return decorator

    @classmethod
    def log(cls, session, operator, template_key=None, **kwargs):
        if session is None or operator is None:
            raise ValueError('db session and operator is neeed!')
        import sys
        method = sys._getframe(1).f_code.co_name
        if method == "<module>":
            return EnvironmentError(unicode('can not run in module level'))
        if not template_key:
            template_name = method
        elif callable(template_key):
            template_name = template_key.__name__
        else:
            template_name = str(template_key)
        template = cls.__log_templates.get(template_name, None)
        return session.add(cls(
            operator_id=operator.id,
            method=method,
            remark=template.render(**kwargs) if template else None
        ))


class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('persons.id'))
    person = db.relationship('Person', backref='notes')
    start_date = db.Column(db.Date, nullable=False)
    _end_date = db.Column(db.Date)
    content = db.Column(db.String, nullable=False)
    _effective = db.Column(db.Boolean, nullable=False, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref='notes')
    create_time = db.Column(db.Date, default=datetime.datetime.now,
                            nullable=False)

    @hybrid_property
    def end_date(self):
        return self._end_date

    @end_date.expression
    def end_date(cls):
        return cls._end_date.label('end_date')

    @end_date.setter
    def end_date(self, val):
        if not (self._effective is None or self._effective):
            raise ValueError('The note is discarded')
        if self.start_date and val and val <= self.start_date:
            raise DateError("end date can't earler than begin date")
        self._end_date = val

    @hybrid_method
    def effective_before(self, date):
        return self._effective and\
            self.start_date <= date and (
                self.end_date is None or self.end_date >= date)

    @effective_before.expression
    def effective_before(cls, date):
        return and_(
            cls._effective.is_(True),
            cls._start_date <= date,
            or_(
                cls._end_date.is_(None),
                cls._end_date >= date))

    @hybrid_property
    def effective(self):
        return self.effective_before(datetime.datetime.now().date())

    @effective.expression
    def effective(cls):
        return cls.effective_before(datetime.datetime.now().date())

    @hybrid_method
    def disable(self):
        if self.finished:
            raise ValueError('The note already finished')
        self._effective = False
        return self._effective

    @hybrid_method
    def finish(self):
        if not self.effective:
            raise ValueError('The note is discarded')
        self.end_date = datetime.datetime.now().date() + timedelta(days=1)
        return self.end_date

    @hybrid_property
    def finished(self):
        return self._end_date and\
            self._end_date < datetime.datetime.now().date() + timedelta(days=2)

    @finished.expression
    def finished(cls):
        return and_(cls._end_date.isnot(None),
                    cls._end_date < datetime.datetime.now().date() +
                    timedelta(days=2))


def paginate(query, page, per_page, error_out=True):
    query.paginate = paginate
    if error_out and page < 1:
        abort(404)
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    if not items and page != 1 and error_out:
        abort(404)
    if page == 1 and len(items) < per_page:
        total = len(items)
    else:
        total = query.order_by(None).count()
    return Pagination(query, page, per_page, total, items)
