# coding=utf-8
import re
import datetime
import calendar
from hashlib import md5
from dateutil.relativedelta import relativedelta
from flask import Flask
from jinja2 import Template
from sqlalchemy import or_, and_, false
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound

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
        return "<UserRoleAssoc(user={user},role={role})>".format(
            user=repr(self.user), role=repr(self.role))

    def __str__(self):
        unicode("{user},{role}").format(
            user=self.user.name, role=self.role.name)


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
        address={address})>".format(
            name=self.name,
            password=self.password,
            active=self.active,
            address=repr(self.address)
        )

    def __str__(self):
        return unicode("{}").format(self.name)

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

    def has_role(self, rolename):
        return rolename in [role.name for role in self.roles]


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
        return unicode("{}").format(self.name)


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
        return "<Address(name='{name}',parent={parent},no='{no}')>".format(
            name=self.name,
            parent=repr(self.parent),
            no=self.no
        )

    def __str__(self):
        return unicode("{name}".format(name=self.name))

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


class PersonStandardAssoc(db.Model):
    __tablename__ = 'person_standard'
    id = db.Column('id', db.Integer, primary_key=True)
    person_id = db.Column(
        'person_id',
        db.Integer,
        db.ForeignKey('persons.id')
    )
    person = db.relationship('Person', backref='stand_assoces')
    standard_id = db.Column(
        'standard_id',
        db.Integer,
        db.ForeignKey('standards.id')
    )
    standard = db.relationship('Standard', backref='person_assoces')
    _start_date = db.Column('start_date', db.Date, nullable=False)
    _end_date = db.Column('end_date', db.Date)

    def __repr__(self):
        return "<PersonStandardAssoc(standard={standard},person={person},\
        _start_date={start_date},_end_date={end_date})>".format(
            standard=repr(self.standard),
            person=repr(self.person),
            start_date=self.start_date,
            end_date=self.end_date
        )

    def __str__(self):
        return unicode("{person},{standard},{start_date},{end_date}").format(
            person=self.person.name,
            standard=self.standard.name,
            start_date=self.start_date,
            end_date=self.end_date if self.end_date else ''
        )

    @hybrid_property
    def start_date(self):
        return self._start_date

    @start_date.setter
    def start_date(self, val):
        self._start_date = val

    @hybrid_property
    def end_date(self):
        return self._end_date

    @end_date.setter
    def end_date(self, val):
        if self.start_date is not None and val <= self.start_date:
            raise DateError("end date can't earler than start date")
        self._end_date = val

    @hybrid_property
    def effective(self):
        return or_(
            self.end_date.is_(None), self.end_date >= datetime.datetime.now())


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
        return "<Person(idcard='{idcard};,name='{name}',address={address},\
        address_detail='{address_detail}',securi_no='{securi_no}',\
        create_time={create_time},status='{status}'\
        ,birthday={birthday})>".format(
            idcard=self.idcard,
            name=self.name,
            address=repr(self.address),
            address_detail=self.address_detail,
            securi_no=self.securi_no,
            create_time=repr(self.create_time),
            status=self.status,
            birthday=repr(self.birthday)
        )

    def __str__(self):
        return unicode('{idcard},{name},{status}'.format(
            idcard=self.idcard,
            name=self.name,
            status=self.status
        ))

    @hybrid_property
    def personal_wage(self):
        return self._personal_wage

    @personal_wage.setter
    def personal_wage(self, val):
        if self.status != self.__status_str(self.NORMAL_RETIRE):
            self._personal_wage = 0.0
        else:
            self._personal_wage = val

    @hybrid_property
    def birthday(self):
        return self._birthday

    @birthday.setter
    def birthday(self, val):
        self._birthday = val

    @property
    def earliest_retire_day(self):
        delta = relativedelta(years=60, months=1)
        retire_day = datetime.date(
            self.birthday.year, self.birthday.month, 1) + delta
        return max(retire_day, _IMPLEMENT_DATE)

    @hybrid_method
    def __status_str(self, index):
        return self.STATUS_CHOICES[index][0]

    @hybrid_method
    def __status_in(self, *args):
        return self.status in (self.__status_str(i) for i in args)

    @hybrid_method
    def __status_is(self, index):
        return self.status == self.__status_str(index)

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
        else:
            raise PersonStatusError('person can not be dead')
        self.dead_day = dead_day
        return self

    def abort(self):
        if self.can_abort_normal:
            self._status = self.__status_str(self.ABROT_UNRETIRE)
        elif self.can_abort_retire:
            self._status = self.__status_str(self.ABORT_RETIRE)
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

    @hybrid_property
    def can_reg(self):
        if self.status is not None:
            return false()
        now = datetime.datetime.now()
        now = datetime.date(now.year, now.month, now.day)
        earlist_engage_day = datetime.date(
            self.birthday.year + _MIN_ENGAGE_IN_AGE, self.birthday.month,
            self.birthday.day)
        return now > earlist_engage_day

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

    @property
    def is_valid_standard_wages(self):
        if self.status != self.__status_str(self.NORMAL_RETIRE):
            return False
        for assoc in self.stand_assoces:
            if assoc.start_date < self.retire_day:
                return False
        if not self.stand_assoces:
            return True
        date_lst = map(lambda a: (a.start_date, a.end_date),
                       self.stand_assoces)
        date_lst.sort(key=lambda x: x[0])

        def f(x, y):
            return (x[1] or False) and x[1] <= y[0] and y
        return reduce(lambda x, y: x and f(x, y), date_lst) and True


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
            name=self.name,
            money=self.money
        )

    def __str__(self):
        return unicode('{name},{money}'.format(
            name=self.name,
            money=self.money
        ))


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
        return "<Bankcard(no='{no}',name='{name}',owner={owner},\
        create_time={create_time})>".format(
            no=self.no,
            name=self.name,
            owner=self.owner.__repr__(),
            create_time=self.create_time.__repr__()
        )

    def __str__(self):
        return unicode('{no}({name})'.format(
            no=self.no,
            name=self.name))


class PayBookItem(db.Model):
    __tablename__ = 'paybookitems'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    direct = db.Column(db.Integer, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('paybookitems.id'))
    parent = db.relationship(
        'PayBookItem', backref='childs', remote_side=[id])

    DEFAULT_ITEMS = (
        PAY, INTER_BANK, BANK, OUGHT_PAY, INCOME, SYS, REMEND, INTER_BANK_FAIL,
        BANK_FAIL) = ('pay', 'internet bank', 'bank', 'ought recive', 'income',
                      'sys', 'remend', 'internet bank fail', 'bank fail')

    def __repr__(self):
        return "<PayBookItem(name='{name}',parent={parent})>".format(
            name=self.name,
            parent=self.parent.__repr__()
        )

    def __str__(self):
        return unicode('{name'.format(name=self.name))

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


class FormatError(RuntimeError):
    ''''''


class PayBook(db.Model):
    __tablename__ = 'paybooks'
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('persons.id'),
                          nullable=False)
    bankcard_id = db.Column(db.Integer, db.ForeignKey('bankcards.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('paybookitems.id'),
                        nullable=False)
    money = db.Column(db.Float(precision=2), nullable=False)
    _peroid = db.Column(db.Date, default=datetime.datetime.now,
                        nullable=False)
    person = db.relationship('Person', backref=db.backref('paybooks',
                                                          order_by=id))
    bankcard = db.relationship('Bankcard', backref=db.backref('paybooks',
                                                              order_by=id))
    _item = db.relationship('PayBookItem')
    create_date = db.Column(
        db.Date, nullable=False, default=datetime.datetime.now)
    create_user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    create_by = db.relationship('User', backref='paybooks')

    def __repr__(self):
        return "<PayBook(money='{money}',person={person},bankcard={bankcard},\
        item={item},peroid={peroid})>".format(
            money=self.money,
            person=repr(self.person),
            bankcard=repr(self.bankcard),
            item=repr(self.item),
            peroid=self.peroid
        )

    def __str__(self):
        return unicode('{person},{bankcard},{item},{money},{peroid}'.format(
            person=self.person,
            bankcard=self.bankcard,
            item=self.item,
            money=self.money,
            peroid=self.peroid
        ))

    @hybrid_property
    def item(self):
        return self._item

    @item.setter
    def item(self, val):
        if isinstance(val, PayBookItem):
            self._item = val
        else:
            self._item = PayBookItem.query.filter(
                PayBookItem.name == val).one()

    @hybrid_property
    def peroid(self):
        return self._peroid

    @peroid.setter
    def peroid(self, val):
        '''val's format is %Y%m, for example:201503'''
        if isinstance(val, (datetime.datetime,)):
            self._peroid = datetime.datetime(val.year, val.month, 1)
        else:
            self._peroid = datetime.datetime.strptime(val, '%Y%m')

    @hybrid_method
    def in_peroid(self, peroid):
        if isinstance(peroid, str):
            peroid = datetime.datetime.strptime(peroid, '%Y%m')
        year, month = peroid.year, peroid.month
        first_date = datetime.datetime(year, month, 1)
        last_date = datetime.datetime(year, month, calendar.monthrange(
            self._peroid.year, self._peroid.month)[1])
        return first_date <= self.peroid <= last_date

    def create_from_report_text(self, text, peroid=None):
        '''
        00000000|xxx|42272519510701001X|60|42052511001|6213360770888888888|
'''
        regex = re.compile(r'^(\d+)\|(.*?)\|(\d{17}[\dX])\|(\d+(?:\.\d+)?)' +
                           r'\|(.*?)\|(\d*)(?:.*?)\|\s+$')
        result = regex.match(text)
        if result is None:
            raise FormatError()
        IDCARDNO, MONEY, BANKCARDNO = 3, 4, 6
        idcard_no = result.group(IDCARDNO)
        bankcard_no = result.group(BANKCARDNO)
        try:
            bankcard = db.session.query(Bankcard).filter(no=bankcard_no).one()
        except NoResultFound:
            bankcard = None
        try:
            person = db.session.query(Person).filter(idcard=idcard_no).one()
            item = db.session.query(
                PayBookItem).filter(name=PayBookItem.SYS).one()
        except NoResultFound as e:
            app.logger.info(e)
            raise e
        self.bankcard = bankcard
        self.person = person
        self.item = item
        self.money = float(result.group(MONEY))
        self.peroid = peroid if peroid else datetime.datetime.now()
        return self

    @classmethod
    def remend_tuple(cls, person, item1, item2, bankcard, money, peroid, user):

        def _remend(item, money):
            return PayBook(
                person=person,
                bankcard=bankcard,
                item=item,
                money=money,
                peroid=peroid,
                create_by=user
            )
        return (_remend(_item, _money)
                for _item, _money in ((item1, -money), (item2, money)))

    def forward_tuple(self, forward_item, bankcard, user):

        def record(item, bankcard, money):
            return PayBook(
                person=self.person,
                peroid=self.peroid,
                bankcard=bankcard,
                item=item,
                create_by=user,
                money=money
            )
        return (record(_item, _bankcard, _money)
                for _item, _bankcard, _money in(
                    (self.item, self.bankcard, -self.money),
                    (forward_item, bankcard, self.money)))


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
        return "<OperationLog(operator={operator},method='{method}',\
        remark='{remark}',time={time})>".format(
            operator=repr(self.operator),
            method=self.method,
            remark=self.remark,
            time=self.time
        )

    def __str__(self):
        return unicode("{operator},{method},{remark},{time}").format(
            operator=self.operator.name,
            method=self.method,
            remark=self.remark,
            time=self.time
        )

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
            operator=operator,
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

    @end_date.setter
    def end_date(self, val):
        if self.start_date and val and val <= self.start_date:
            raise DateError("end date can't earler than begin date")
        self._end_date = val

    @hybrid_property
    def effective(self):
        return and_(
            self.end_date.isnot(None),
            self.start_date <= datetime.datetime.now(),
            self._effective
        )

    @hybrid_method
    def disable(self):
        self._effective = False

    @hybrid_method
    def finish(self):
        self.end_date = datetime.datetime.now()


def test():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    db.create_all()
