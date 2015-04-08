# coding=utf-8
import hashlib
import re
from collections import namedtuple
from functools import partial
from datetime import datetime
import flask
from flask import (
    render_template, request, session, abort, redirect, current_app, url_for
)
from jinja2 import Template
from sqlalchemy import and_, func
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.sql import exists
from flask.ext.login import (
    LoginManager, current_user, login_user, login_required, logout_user
)
from flask.ext.principal import (
    Principal, Identity, identity_loaded, UserNeed, RoleNeed, identity_changed,
    Permission
)
from models import (
    User, Role, Address, Person, Standard, PersonStandardAssoc, Bankcard,
    PersonStatus, PersonAgeError, PayBookItem, PayBook, OperationLog, db, app
)

app.config.from_pyfile('config.cfg')
db.create_all()

__DEFAULT_PAGE_SIZE = 10
SUCCESS = 'succes'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

Principal(app)
admin_required = Permission(RoleNeed('admin')).require()

__log_templates = {}


def log_template(template=None, name=None):
    def decorator(f):
        __log_templates[name or f.__name__]\
            = Template(template) if template else None
        return f
    return decorator


def _operationlog(*args, **kwargs):
    import sys
    method = sys._getframe(1).f_code.co_name
    if method == "<module>":
        return
    if not args:
        template_name = method
    elif callable(args[0]):
        template_name = args[0].__name__
    else:
        template_name = str(args[0])
    template = __log_templates.get(template_name, None)
    db.session.add(
        OperationLog(
            operator=current_user,
            method=method,
            remark=template.render(**kwargs) if template else None
        )
    )


def _is_empty(arg):
    return arg is None or arg == 'None' or arg.strip() == ''


def _pagination_to_dict(pagination):
    return {
        'items': [_obj_to_dict(address) for address in pagination.items],
        'pages': pagination.pages,
        'prev_num': pagination.prev_num,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'nex_num': pagination.next_num
    }


def _obj_to_dict(obj):
    obj_dict = obj.__dict__
    return dict(
        (key, obj_dict[key]) for key in obj_dict if not key.startswith('_')
    )


def _set_back_url(back_url=None, error=None):
    if not back_url:
        back_url = '/index.html'
    session['back_url'] = back_url
    session['error'] = error


def to_404_page(back_url=None, error=None):
    _set_back_url(back_url, error)
    abort(404)


def to_500_page(back_url=None, error=None):
    _set_back_url(back_url, error)
    abort(500)


def to_403_page(back_url=None, error=None):
    _set_back_url(back_url, error)
    abort(403)


@login_manager.user_loader
def load_user(userid):
    try:
        return User.query.filter(User.id == userid).one()
    except NoResultFound:
        return {
            'is_authenticated': (lambda: False),
            'is_active': (lambda: False),
            'is_anonymous': (lambda: True),
            'get_id': (lambda: None)
        }


AddressNeed = namedtuple('AddressNeed', ['method', 'value'])
AddressAccessNeed = partial(AddressNeed, 'access')


class AddressAccessPermission(Permission):
    def __init__(self, address_id):
        need = AddressAccessNeed(unicode('{}'.format(address_id)))
        super(AddressAccessPermission, self).__init__(need)


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))
    if hasattr(current_user, 'address'):
        ids = [address.id for address in current_user.address.descendants()]
        Address.query = Address.query.filter(Address.id.in_(ids))
        Person.query = Person.query.filter(Person.address_id.in_(ids))
        for id in ids:
            identity.provides.add(AddressAccessPermission(id))


@app.template_global
def request_args_to_dict(request, extra={}):
    extra = extra.copy()
    extra.update(request.args.to_dict())
    return extra


@app.template_global
def personstatus():
    return PersonStatus


@app.template_global
def paybookitems():
    return PayBookItem


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def page_error(error):
    return render_template('500.html'), 500


@app.errorhandler(403)
def page_forbiden(error):
    return render_template('403.html'), 403


@app.before_request
def before_request():
    session['error'] = None
    if request.method == 'POST':
        if request.form.get('address_id', None):
            if not AddressAccessPermission(
                    int(request.form['address_id'])
            ).can():
                to_403_page(
                    error='You can not access address with id{}'.format(
                        request.form['address_id']
                    ))
        method = request.form.get('_method', '').upper()
        if method:
            request.environ['REQUEST_METHOD'] = method
            ctx = flask._request_ctx_stack.top
            ctx.url_adapter.default_method = method
            assert request.method == method


@app.route('/', methods=['GET'])
@login_required
def main_page():
    return render_template('index.html')


@app.route('/index.html', methods=['GET'])
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@log_template()
def login():
    if request.method == 'GET':
        return render_template('login.html')

    def _redirect():
        return redirect(
            '/login?next={}'.format(request.args.get('next') or '/'))
    try:
        token = User(
            name=request.form['name'],
            password=request.form['password']
        )
        user = User.query.filter(User.name == request.form['name']).one()
        if token != user:
            return _redirect()
    except NoResultFound:
        return _redirect()
    login_user(user)
    identity_changed.send(
        current_app._get_current_object(),
        identity=Identity(user.id))
    _operationlog()
    return redirect(request.args.get('next') or '/')


@app.route('/logout')
@login_required
@log_template()
def logout():
    logout_user()
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    _operationlog(time=datetime.now())
    return redirect('/login')


@app.route('/user/add', methods=['GET', 'POST'])
@admin_required
@log_template("{{ user.name }}")
def user_add():
    if request.method == 'GET':
        return render_template(
            'user_add.html'
        )
    user = User(
        name=request.form['name'],
        password=request.form['password'],
        active=True if request.form['is_activate'] else False
    )
    db.session.add(user)
    _operationlog(user=user, time=datetime.now())
    db.session.commit()
    return SUCCESS


def _change_password(user, invalid_url):
    def validate_form(form):
        for field in (form['old_password'], form['new_password'],
                      form['password_confirm']):
            if not field or field == '':
                return False
        if form['new_password'] != form['password_confirm']:
            return False
        return True
    if not validate_form(request.form):
        return redirect(invalid_url)
    user.password = request.form['new_password']
    db.session.commit()


@app.route('/user/<int:pk>/changepassword', methods=['POST', 'GET'])
@admin_required
@log_template("{{ user.name }}")
def user_admin_change_password(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        to_404_page()
    if request.method == 'GET':
        return render_template(
            'user_change_password.html',
            user=user
        )
    _change_password(user, '/user/{}/changepassword'.format(pk))
    _operationlog(user=user, time=datetime.now())
    return SUCCESS


@app.route(
    '/user/changepassword', methods=['GET', 'POST']
)
@login_required
@log_template()
def user_changpassword():
    if request.method == 'GET':
        return render_template(
            'user_chang_password.html',
            user=current_user
        )
    _change_password(current_user, 'user/changepassword')
    _operationlog(time=datetime.now())
    return SUCCESS


@app.route(
    '/user/<int:pk>/admin?isactive=<string:active>',
    methods=['POST', 'GET']
)
@admin_required
@log_template("{{ user.name }}")
def user_deactive(pk, active):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        to_404_page()
    active = True if active == 'True' else False
    if request.method == 'GET':
        return render_template(
            'user_deactive.html',
            user=user,
            active=active
        )
    user.active = active
    _operationlog(user=user, time=datetime.now())
    db.session.commit()
    return SUCCESS


@app.route('/address/add', methods=['GET', 'POST'])
@login_required
@admin_required
def address_add():
    if request.method == 'GET':
        return render_template('address_add.html',
                               addresses=Address.query.all())
    parent_id = request.form['parent_id']
    no = request.form['no']
    name = request.form['name']
    if parent_id:
        try:
            parent = Address.query.filter(Address.id == parent_id).one()
        except NoResultFound:
            to_404_page('/address/add', 'parent not find!')
    else:
        parent = None
    address = Address(parent=parent, no=no, name=name)
    db.session.add(address)
    db.session.commit()
    return SUCCESS


@app.route('/address/delete/<pk>', methods=['POST'])
@login_required
@admin_required
def address_delte(pk):
    try:
        address = Address.query.filter(Address.id == pk).one()
    except NoResultFound:
        to_404_page(error='address with pk:{} not exists'.format(pk))
    db.session.delete(address)
    db.session.commit()
    return SUCCESS


@app.route('/address/update/<pk>', methods=['POST', 'GET'])
@login_required
@admin_required
def address_update(pk):
    try:
        address = Address.query.filter(Address.id == pk).one()
    except NoResultFound:
        to_404_page(error='address with pk:{} not exists'.format(pk))
    if address.parent:
        address_list = Address.query.filter(Address.id != address.parent.id)\
                                    .all()
    else:
        address_list = Address.query.all()
    if request.method == 'GET':
        return render_template(
            'address_update.html',
            address=address,
            address_list=address_list
        )
    parent_id = request.form['parent_id']
    address.name = request.form['name']
    address.no = request.form['no']
    if parent_id:
        try:
            parent = Address.query.filter(Address.id == parent_id).one()
        except NoResultFound:
            to_404_page(error='/address/update/{pk}'.format(pk=pk))
        address.parent = parent
    else:
        address.parent = None
    db.session.commit()
    return SUCCESS


@app.route('/address/<pk>', methods=['GET'])
@login_required
def address_get(pk):
    try:
        address = Address.query.filter(Address.id == pk).one()
    except NoResultFound:
        to_404_page(error='address with pk:{} not exists'.format(pk))
    return render_template('address_detail.html', address=address)


@app.route('/address/ajax/<pk>', methods=['GET'])
@login_required
def address_get_ajax(pk):
    try:
        address = Address.query.filter(Address.id == pk).one()
    except NoResultFound:
        to_404_page(error='address with pk{} not exists'.format(pk))
    return flask.json.dumps(_obj_to_dict(address))


@app.route('/address/pk/name=<name>&no=<no>', methods=['GET'])
@login_required
def address_get_pk(name, no):
    query = Address.query
    if not _is_empty(name):
        query = query.filter(Address.name == name)
    if not _is_empty(no):
        query = query.filter(Address.no == no)
    try:
        address = query.one()
    except NoResultFound:
        to_404_page(error='address not exists')
    except MultipleResultsFound:
        to_500_page(error='Too many address find')
    return '{}'.format(address.id)


@app.route(
    '/address/list/page=<int:page>&size=<int:size>',
    methods=['GET'],
    endpoint='address_list'
)
@app.route(
    '/address/list/page=<int:page>',
    methods=['GET'],
)
@login_required
def address_list(page=1, size=__DEFAULT_PAGE_SIZE):
    return render_template(
        'address_list.html',
        pagination=Address.query.paginate(page, size),
        extra={}
    )


@app.route(
    '/address/search/no=<string:no>&name=<string:name>' +
    '&page=<int:page>&size=<int:size>',
    methods=['GET']
)
@login_required
def address_search(no=None, name=None, page=1, size=__DEFAULT_PAGE_SIZE):
    query = Address.query
    if not _is_empty(no):
        query = query.filter(Address.no.like(u'{}%'.format(no)))
    if not _is_empty(name):
        query = query.filter(Address.name.like(u'{}%'.format(name)))
    return render_template(
        'address_list.html',
        pagination=query.paginate(page, size),
        extra={'no': no, 'name': name}
    )


@app.route(
    '/address/search/ajax/no=<string:no>&name=<string:name>' +
    '&page=<int:page>&size=<int:size>',
    methods=['GET'],
    endpoint='address_search_ajax'
)
@login_required
def address_search_ajax(no=None, name=None, page=1, size=__DEFAULT_PAGE_SIZE):
    query = Address.query
    if not _is_empty(no):
        query = query.filter(Address.no.like(u'{}%'.format(no)))
    if not _is_empty(name):
        query = query.filter(Address.name.like(u'{}%'.format(name)))
    return flask.json.dumps(_pagination_to_dict(query.paginate(page, size)))


@app.route(
    '/address/list/ajax/page=<int:page>',
    methods=['GET'],
    endpoint='address_list_ajax'
)
@app.route(
    '/address/list/ajax/page=<int:page>&size=<int:size>',
    methods=['GET'],
    endpoint='address_list_ajax'
)
@login_required
def address_list_ajax(page=1, size=__DEFAULT_PAGE_SIZE):
    return flask.json.dumps(
        _pagination_to_dict(Address.query.paginate(page, size))
    )


person_admin_required = Permission(RoleNeed('person_admin')).require()
bankcard_admin_required = Permission(RoleNeed('bankcard_admin')).require()
accountant_required = Permission(RoleNeed('accountant')).require()
accountant_admin_required = Permission(RoleNeed('accountant_admin')).require()


@app.route(
    '/person/add/',
    methods=['GET', 'POST'],
)
@login_required
@person_admin_required
def person_add():
    if request.method == 'GET':
        return render_template(
            'person_add.html',
            addresses=Address.query.order_by(Address.parent_id).all()
        )
    try:
        address = Address.query.filter(
            Address.id == request.form['address_id']).one()
    except NoResultFound:
        to_404_page(error='address not exists')
    person = Person(
        idcard=request.form['idcard'],
        birthday=datetime.strptime(request.form['idcard'][6:14], '%Y%m%d'),
        name=request.form['name'],
        address=address,
        address_detail=request.form['address_detail'],
        securi_no=request.form['securi_no'],
        personal_wages=request.form['personal_wages'],
        status=PersonStatus.STATUS_CHOICES[PersonStatus.REG][0],
        create_by=current_user
    )
    if not person.can_reg():
        to_500_page('person is too young to reg')
    db.session.add(person)
    db.session.commit()
    return SUCCESS


@app.route(
    '/person/delete/<int:pk>',
    methods=['POST']
)
@login_required
@admin_required
@log_template("{{ person.id }}:{{ person.idcard }},{{ person.name }}," +
              "{{ person.status }}")
def person_delete(pk):
    try:
        person = Person.query.filter(Person.id == pk).one()
    except NoResultFound:
        to_404_page(error='person with pk{} not exists'.format(pk))
    _operationlog(person=person)
    db.session.delete(person)
    db.session.commit()
    return SUCCESS


def _differ_obj(obj, fields):
    obj_values = [getattr(obj, field, None) for field in fields]
    values = [request.form.get(field, None) for field in fields]
    old_values = dict(
        (e[0], e[1][0])
        for e in zip(fields, zip(obj_values, values))
        if str(e[1][0]) != str(e[1][1])
    )
    return str(old_values).replace(':', '=').replace('{', '').replace('}', '')


@app.route(
    '/person/update/<int:pk>',
    methods=['POST', 'GET']
)
@login_required
@person_admin_required
@log_template("{{ person.id }}:{{ remark }}")
def person_update(pk):
    try:
        person = Person.query.filter(Person.id == pk).one()
    except NoResultFound:
        to_404_page(error='person with pk{} do not exists'.format(pk))
    if request.method == 'GET':
        return render_template(
            'person_update.html',
            person=person,
            addresses=Address.query.filter(Address.id != person.address.id)
            .all()
        )
    _operationlog(
        person=person,
        remark=_differ_obj(
            person,
            ['idcard', 'name', 'birthday', 'address_id', 'address_detail',
             'securi_no', 'personal_wages']
        )
    )
    person.idcard = request.form['idcard']
    person.name = request.form['name']
    person.birthday = datetime.strptime(request.form['birthday'], '%Y-%m-%d')
    person.address_id = int(request.form['address_id'])
    person.address_detail = request.form['address_detail']
    person.securi_no = request.form['securi_no']
    person.personal_wages = float(request.form['personal_wages'])
    db.session.commit()
    return SUCCESS


@app.route(
    '/person/<int:pk>/retire-reg/',
    methods=['GET', 'POST']
)
@login_required
@person_admin_required
@log_template("{{ person.id }}:{{ person.status }}")
def person_retire_reg(pk):
    try:
        person = Person.query.filter(Person.id == pk).one()
    except NoResultFound:
        to_404_page(error='person with pk:{} do not exists'.format(pk))
    if not PersonStatus.canretire(person):
        to_500_page(error='person can not retire')
    if request.method == 'GET':
        return render_template(
            'person_retire_reg.html',
            person=person
        )
    _operationlog(person=person)
    try:
        person.retire(
            datetime.strptime(request.form['retire_day'], '%Y-%m-%d'))
    except PersonAgeError:
        to_500_page(error=unicode('person is too young to retire'))
    db.session.commit()
    return SUCCESS


@app.route(
    '/person/<int:pk>/dead-reg/',
    methods=['GET', 'POST']
)
@login_required
@person_admin_required
@log_template("{{ person.id }}:{{ person.status }}")
def person_dead_reg(pk):
    try:
        person = Person.query.filter(Person.id == pk).one()
    except NoResultFound:
        to_404_page(error='person with pk:{} does not find'
                    .format(pk))
    if not PersonStatus.candead(person):
        to_500_page(error='person can not be dead')
    if request.method == 'GET':
        return render_template(
            '/person_dead_reg.html',
            person=person
        )
    _operationlog(person=person)
    person.dead(
        datetime.strptime(request.form['dead_day'], '%Y-%m-%d'))
    db.session.commit()
    return SUCCESS


@app.route(
    '/person/search/idcard=<string:idcard>&name=<string:name>' +
    '&address=<string:address>&page=<int:page>&size=<int:size>',
    methods=['GET'],
    endpoint='person_search'
)
@login_required
def person_search(idcard=None, name=None, address=None, page=1,
                  size=__DEFAULT_PAGE_SIZE):
    query = Person.query
    if not _is_empty(idcard):
        query = query.filter(Person.idcard.like(u'{}%'.format(idcard)))
    if not _is_empty(name):
        query = query.filter(Person.name.like(u'{}%'.format(name)))
    if not _is_empty(address):
        stmt = exists().where(
            and_(
                Address.id == Person.address_id,
                Address.name.like(u'{}%'.format(address))
            )
        )
        query = query.filter(stmt)
    pagination = query.paginate(page, size)
    return render_template(
        'person_list.html',
        pagination=pagination,
        extra={
            'idcard': idcard,
            'name': name,
            'address': address
        }
    )


@app.route(
    '/person/<int:pk>',
    methods=['GET']
)
@login_required
def person_detail(pk):
    try:
        person = Person.query.filter(Person.id == pk).one()
    except NoResultFound:
        to_404_page(error='person with pk:{} do not exists'.format(pk))
    return render_template('person_detail.html', person=person)


@app.route(
    '/person/detail/ajax/<int:pk>',
    methods=['GET']
)
@login_required
def person_detail_ajax(pk):
    try:
        person = Person.query.filter(Person.id == pk).one()
    except NoResultFound:
        to_404_page(error='person with pk:{} do not exists'.format(pk))
    return flask.json.dumps(_obj_to_dict(person))


@app.route(
    '/person/search/ajax/idcard=<string:idcard>&name=<string:name>' +
    '&address=<string:address>&page=<int:page>&size=<int:size>',
    methods=['GET']
)
@login_required
def person_search_ajax(idcard=None, name=None, address=None, page=1,
                       size=__DEFAULT_PAGE_SIZE):
    query = Person.query
    if not _is_empty(idcard):
        query = query.filter(Person.idcard.like(u'{}%'.format(idcard)))
    if not _is_empty(name):
        query = query.filter(Person.name.like(u'{}%'.format(name)))
    if not _is_empty(address):
        stmt = exists().where(
            and_(
                Address.id == Person.address_id,
                Address.name.like(u'{}%'.format(address))
            )
        )
        query = query.filter(stmt)
    return flask.json.dumps(_pagination_to_dict(query.paginate(page, size)))


@app.route(
    '/standard/bind/batch/',
    methods=['GET', 'POST']
)
@login_required
@person_admin_required
@log_template("{{ person.id }}")
def standard_batch_bind():
    if request.method == 'GET':
        return render_template(
            'standard_bind_batch.html',
            standards=Standard.query.all()
        )
    query = Person.query
    if request.form['min_birthday']:
        query = query.filter(
            Person.birthday >= request.form['min_birthday'])
    if request.form['max_birthday']:
        query = query.filter(
            Person.birthday <= request.form['max_birthday'])
    if request.form['status'] not in (
            PersonStatus[PersonStatus.NORMAL_RETIRE][0],
            PersonStatus[PersonStatus.SUSPEND_RETIRE][0]
    ):
        to_500_page(
            back_url='/standard/bind/batch/',
            error='person can not bind standard')
    if request.form['status']:
        query = query.filter(Person.status == request.form['status'])
    if request.form['excepts']:
        query = query.filter(
            ~Person.idcard.in_(request.form['excepts'].splitlines())
        )
    try:
        standard = Standard.query.filter(
            Standard.id == request.form['standard']
        ).one()
    except NoResultFound:
        to_404_page(error='standard does not exists')
    if request.form['start_date']:
        start_date = datetime.strptime(
            request.form['start_date'], '%Y-%m-%d')
        start_date = datetime(start_date.year, start_date.month, 1)
    else:
        now = datetime.now()
        start_date = datetime(now.year, now.month, 1)
    if request.form['end_date']:
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        end_date = datetime(end_date.year, end_date.month, 1)
    else:
        end_date = None
    for person in query.all():
        start_date = max(start_date, person.retire_day_func('2011-07-01'))
        db.session.add(
            PersonStandardAssoc(
                person_id=person.id,
                standard_id=standard.id,
                start_date=start_date,
                end_date=end_date
            )
        )
        _operationlog(person=person)
    db.session.commit()
    return SUCCESS


@app.route(
    '/standard/bind/idcard=<idcard>',
    methods=['GET', 'POST']
)
@login_required
@person_admin_required
@log_template("{{ person.id }}")
def standard_bind(idcard):
    try:
        person = Person.query.filter(
            Person.idcard == idcard
        ).one()
    except NoResultFound:
        to_404_page(error='person with idcard:{} does not exists'
                    .format(idcard))
    except MultipleResultsFound:
        to_500_page(error='Too many person find')
    if request.method == 'GET':
        return render_template(
            'standard_bind.html',
            person=person,
            standards=Standard.query.all()
        )
    if request.form['start_date']:
        start_date = datetime.strptime(
            request.form['start_date'], '%Y-%m-%d')
        start_date = datetime(start_date.year, start_date.month, 1)
    else:
        to_500_page(error='start_date required')
    if request.form['end_date']:
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        end_date = datetime(end_date.year, end_date.month, 1)
    else:
        end_date = None
    try:
        standard = Standard.query.filter(
            Standard.id == request.form['standard']
        ).one()
    except NoResultFound:
        to_404_page(error='standard does not exists')
    start_date = max(person.retire_day_func('2011-07-01'), start_date)
    db.session.add(
        PersonStandardAssoc(
            person_id=person.id,
            standard_id=standard.id,
            start_date=start_date,
            end_date=end_date
        )
    )
    _operationlog(person=person)
    db.session.commit()
    return SUCCESS


@app.route(
    '/standard/debind/idcard=<idcard>',
    methods=['GET', 'POST']
)
@login_required
@person_admin_required
@log_template("{{ person.id }}:{{ standard.name }}," +
              "{{ assoc.start_date }}," +
              "{{ assoc.end_date }}")
def standard_debind(idcard):
    try:
        person = Person.query.filter(Person.idcard == idcard).one()
    except NoResultFound:
        to_404_page(error='person with idcard:{} does not exists'
                    .format(idcard))
    if request.method == 'GET':
        return render_template(
            'standard_debind.html',
            person=person
        )
    standard = Standard.query.filter(
        Standard.id == request.form['standard']
    ).one()
    _operationlog(
        person=person,
        standard=standard,
        assoc=PersonStandardAssoc.query.filter(
            PersonStandardAssoc.person_id == person.id,
            PersonStandardAssoc.standard_id == standard.id
        ).one()
    )
    person.standard_wages.remove(standard)
    db.session.commit()
    return SUCCESS


@app.route(
    '/standard/list/idcard=<string:idcard>',
    methods=['GET']
)
@login_required
def standard_list(idcard):
    try:
        person = Person.query.filter(Person.idcard == idcard).one()
    except NoResultFound:
        to_404_page(error='person with idcard:{} does not exists'
                    .format(idcard))
    return render_template(
        'standard_list.html',
        assoces=PersonStandardAssoc.query.filter(
            PersonStandardAssoc.person_id == person.id
        ).all()
    )


@app.route(
    '/bankcard/add',
    methods=['GET', 'POST']
)
@login_required
@bankcard_admin_required
def bankcard_add():
    if request.method == 'GET':
        return render_template(
            'bankcard_add.html'
        )
    db.session.add(Bankcard(
        no=request.form['no'],
        name=request.form['name'],
        create_by=current_user
    ))
    db.session.commit()
    return SUCCESS


@app.route(
    '/bankcard/bind/bankcard-no=<no>&idcard=<idcard>',
    methods=['GET', 'POST']
)
@login_required
@bankcard_admin_required
@log_template("{{ person.id }}:{{ bankcard.id }}")
def bankcard_bind(no, idcard):
    try:
        bankcard = Bankcard.query.filter(Bankcard.no == no).one()
        owner = Person.query.filter(
            Person.idcard == idcard
        ).one()
    except NoResultFound:
        if bankcard:
            to_404_page(error='person with idcard:{} does not exists'
                        .format(idcard))
        else:
            to_404_page(error='bankcard with no:{} does not exists'
                        .format(no))
    if request.method == 'GET':
        return render_template(
            'bankcard_bind.html',
            bankcard=bankcard,
            owner=owner
        )
    bankcard.owner = owner
    _operationlog(person=owner, bankcard=bankcard)
    db.session.commit()
    return SUCCESS


@app.route(
    '/bankcard/debind?no=<no>',
    methods=['GET', 'POST']
)
@login_required
@bankcard_admin_required
@login_manager("{{ bankcard.owner.id }}:{{ bankcard.no }},{{ bankcard.name}}")
def bankcard_debind(no):
    try:
        bankcard = Bankcard.query.filter(Bankcard.no == no).one()
    except NoResultFound:
        to_404_page(error=u'no result find')
    if request.method == 'GET':
        return render_template(
            'bankcard_debind.html',
            bankcard=bankcard
        )
    _operationlog(bankcard=bankcard)
    bankcard.owner = None
    db.session.commit()
    return SUCCESS


@app.route(
    '/bankcard/update/<int:pk>',
    methods=['GET', 'POST']
)
@login_required
@bankcard_admin_required
@log_template("{{ person.id }}:{{ remark }}")
def bankcard_update(pk):
    try:
        bankcard = Bankcard.query.filter(Bankcard.id == pk).one()
    except NoResultFound:
        to_404_page(error='bankcard with pk:{} does not exists'
                    .format(pk))
    if request.method == 'GET':
        return render_template(
            'bankcard_update.html',
            bankcard=bankcard
        )
    _operationlog(
        person=bankcard.owner, remark=_differ_obj(bankcard, ['no', 'name']))
    bankcard.no = request.form['no']
    bankcard.name = request.form['name']
    db.session.commit()
    return SUCCESS


@app.route(
    '/bankcard/search/ownerid=<ownerid>&idcard=<idcard>&no=<no>&name=<name>' +
    '&page=<page>&size=<size>',
    methods=['GET']
)
@login_required
def bankcard_search(owner, idcard, no, name, page, size):
    query = Bankcard.query
    if not _is_empty(owner):
        stmt = exists().where(
            and_(
                Bankcard.owner_id == Person.id,
                Person.id == owner
            )
        )
        query = query.filter(stmt)
    if not _is_empty(idcard):
        stmt = exists().where(
            and_(
                Bankcard.owner_id == Person.id,
                Person.idcard.like(u'{}%'.format(idcard))
            )
        )
        query = query.filter(stmt)
    if not _is_empty(no):
        query = query.filter(Bankcard.no.like('u{}%'.format(no)))
    if not _is_empty(name):
        query = query.filter(Bankcard.name.like('u{}%'.format(name)))
    pagination = query.paginate(page, size)
    return render_template(
        'bankcard_list.html',
        pagination=pagination,
        extra={
            'owner': owner,
            'idcard': idcard,
            'no': no,
            'name': name,
            'page': page,
            'size': size
        }
    )


@app.route(
    '/bankcard/delete/<int:pk>',
    methods=['POST']
)
@login_required
@bankcard_admin_required
@log_template("{{ bankcard.owner.id }}:{{ bankcard.no }},{{ bankcard.name }}")
def bankcard_delete(pk):
    try:
        bankcard = Bankcard.query.filter(Bankcard.id == pk).one()
    except NoResultFound:
        to_404_page(error='bankcard with pk:{} does not exists'
                    .format(pk))
    _operationlog(bankcard=bankcard)
    db.session.delete(bankcard)
    db.session.commit()
    return SUCCESS


@app.route(
    '/bankcard/detail/<pk>',
    methods=['GET']
)
@login_required
def bankcard_detail(pk):
    try:
        bankcard = Bankcard.query.filter(Bankcard.id == pk).one()
    except NoResultFound:
        to_404_page(error='bankcard with pk:{} does not exists'
                    .format(pk))
    return render_template(
        'bankcard_detail.html',
        bankcard=bankcard
    )


@app.route(
    '/paybootitem/add',
    methods=['POST', 'GET']
)
@login_required
@accountant_admin_required
def pay_book_item_add():
    if request.method == 'GET':
        return render_template(
            'pay_book_item_add.html',
            items=PayBookItem.query.all()
        )

    def validate_form():
        if not request.form['name']:
            return False
        if not request.form['direct']:
            return False
        return True
    if not validate_form():
        redirect('/paybootitem/add')
    db.session.add(
        PayBookItem(
            name=request.form['name'],
            direct=request.form['direct'],
            parent_id=request.form['parent_id']
        )
    )
    db.session.commit()
    return SUCCESS


@app.route(
    '/paybookitem/<int:pk>/delete',
    methods=['POST', 'GET']
)
@login_required
@accountant_admin_required
def pay_book_item_delete(pk):
    try:
        item = PayBookItem.query.filter(PayBookItem.id == pk).one()
    except NoResultFound:
        to_404_page(error=unicode('not pay book item find with pk:{}').format(
            pk))
    if request.method == 'GET':
        return render_template(
            'pay_book_item_delete.html',
            item=item
        )
    db.session.delete(item)
    db.session.commit()
    return SUCCESS


@app.route(
    '/paybook/import',
    methods=['POST', 'GET']
)
@login_required
@accountant_required
@log_template("{{ checksum }}")
def pay_book_upload():
    if request.method == 'GET':
        return render_template('pay_book_upload.html')

    def validate_form():
        if not request.files.get('file', None):
            return False
        try:
            datetime.strptime(request.form['peroid'], '%Y%m')
        except ValueError:
            return False
        return True
    if not validate_form():
        redirect('/paybook/import')
    stmt = exists().where(and_(
        PayBook.item_id == PayBookItem.id,
        PayBookItem.name == PayBookItem.SYS))
    peroid = str(request.form['peroid'])
    if PayBook.query.filter(stmt, PayBook.in_peroid(peroid)).count() > 0:
        to_500_page(
            back_url='/paybook/import',
            error=unicode('the peroid already exists'))
    file = request.files['file']
    try:
        md5 = hashlib.md5('')
        for line in file:
            md5.update(line)
            record = PayBook().create_from_report_text(
                line, request.form['peroid'])
            record.create_by = current_user
            db.session.add(record)
            db.session.add(PayBook(
                person=record.person,
                bankcard=record.bankcard,
                peroid=record.peroid,
                item=PayBookItem.query.filter(
                    PayBookItem.name == PayBookItem.OUGHT_PAY).one(),
                money=-record.money,
                create_by=current_user))
    except (NoResultFound, ValueError) as e:
        app.logger.info(e)
        db.session.rollback()
        to_500_page(error=e.message)
    _operationlog(checksum=md5.hexdigest())
    db.session.commit()
    return SUCCESS


def _paybook_query(query, idcard=None, bankcard=None, peroid=None, item=None):
    if idcard:
        query = query.filter(exists().where(and_(
            PayBook.person_id == Person.id,
            Person.idcard == idcard)))
    if bankcard:
        query = query.filter(exists().where(and_(
            PayBook.bankcard_id == Bankcard.id,
            Bankcard.no == bankcard)))
    if peroid:
        query = query.filter(PayBook.in_peroid(peroid))
    if item:
        query = query.filter(exists().where(and_(
            PayBook.item_id == PayBookItem.id,
            PayBookItem.name == item)))
    return query


@app.route(
    '/paybook/amend/idcard=<idcard>&peroid=<peroid>',
    methods=['GET', 'POST']
)
@login_required
@accountant_required
@log_template("{{ idcard }},{{ peroid }}")
def paybook_amend(idcard, peroid):
    paybooks = _paybook_query(
        db.session.query(
            PayBook.id,
            PayBook.person,
            PayBook.item,
            PayBook.bankcard,
            PayBook.peroid,
            func.sum(PayBook.money).label('money')),
        peroid=peroid,
        idcard=idcard,
        item=PayBookItem.OUGHT_PAY
    ).group_by(
        PayBook.bankcard_id
    ).having(
        func.sum(PayBook.money) > 0.001
    ).all()
    if request.method == 'GET':
        return render_template('paybook_amend.html', paybooks=paybooks)

    def validate_form():
        regex = re.compile(r'^(\d{19})|(\d{2}-\d{15})$')
        if not regex.match(request.form['bankcard']):
            return False
        try:
            float(request.form['money'])
        except ValueError:
            return False
        return True
    back_url = url_for('paybook_amend', idcard=idcard, peroid=peroid)
    if not validate_form():
        redirect(back_url)
    try:
        bankcard = Bankcard.query.filter(
            Bankcard.no == request.form['bankcard']).one()
    except NoResultFound:
        to_404_page(
            back_url=back_url,
            error=unicode('no bankcard find with no{}').format(
                request.form['bankcard'])
        )
    remend_item = PayBookItem.query.filter(
        PayBookItem.name == PayBookItem.REMEND).one()
    for paybook in paybooks:
        db.session.add_all(
            paybook.forward_tuple(remend_item, paybook.bankcard, current_user))
    db.session.add_all(
        PayBook.remend_tuple(
            paybook.person, paybook.item, remend_item, bankcard,
            request.form['money'], paybook.peroid, current_user))
    _operationlog(idcard=idcard, peroid=peroid)
    db.session.commit()
    return SUCCESS


@app.route(
    'paybook/froward/batch',
    methods=['GET', 'POST']
)
@login_required
@accountant_admin_required
@log_template("{{ peroid }},{{ item1.name }},{{ item2.name }}")
def paybook_batch_forward():
    if request.method == 'GET':
        return render_template('paybook_batch_forward.html')
    regex = re.compile(r'\d{4}(:?(:?0[1-9])|(:?1[0-2]))')
    if not regex.match(request.form['peroid']):
        redirect('paybook/froward/batch')
    paybooks = _paybook_query(
        db.session.query(
            PayBook.id,
            PayBook.bankcard,
            PayBook.item,
            PayBook.peroid,
            PayBook.person,
            func.sum(PayBook.money).label('money')),
        item=request.form['item1'],
        peroid=request.form['peroid']
    ).group_by(
        PayBook.person_id
    ).having(func.sum(PayBook.money) != 0).all()
    try:
        forward_item = PayBookItem.query.filter(
            PayBookItem.name == request.form['item2']).one()
    except NoResultFound:
        to_404_page(error=unicode('no paybook item find with name:{}').format(
            request.form['item2']))
    for paybook in paybooks:
        db.session.add_all(paybook.forward_tuple(
            forward_item, paybook.bankcard, current_user))
    db.session.commit()
    _operationlog(
        peroid=request.form['peroid'], item1=paybook.item, item2=forward_item)
    return SUCCESS


@app.route(
    '/paybook/tointerbank?peroid=<peroid>',
    methods=['GET', 'POST']
)
@login_required
@accountant_required
@log_template("{{ peroid }}")
def to_inter_bank(peroid):
    if request.method == 'GET':
        return render_template('to_inter_bank.html')
    paybooks = _paybook_query(
        db.session.query(
            PayBook.id,
            PayBook.person,
            PayBook.item,
            PayBook.bankcard,
            PayBook.peroid,
            func.sum(PayBook.money).label('money')),
        peroid=peroid,
        item=PayBookItem.OUGHT_PAY
    ).group_by(
        PayBook.bankcard_id
    ).having(
        func.sum(PayBook.money) > 0.001
    ).all()

    inter_bank_item = PayBookItem.query.filter(
        PayBookItem.name == PayBookItem.INTER_BANK).one()
    for paybook in paybooks:
        db.session.add_all(paybook.forward_tuple(
            inter_bank_item, paybook.bankcard, current_user))
    db.session.commit()
    _operationlog(peroid=peroid)
    return SUCCESS


@app.route(
    '/paybook/tobank/peroid=<peroid>',
    methods=['GET', 'POST']
)
@login_required
@accountant_required
@log_template("{{ peroid }}")
def to_bank(peroid):
    if request.method == 'GET':
        return render_template('to_bank.html')

    paybooks = _paybook_query(
        db.session.query(
            PayBook.id,
            PayBook.person,
            PayBook.item,
            PayBook.bankcard,
            PayBook.peroid,
            func.sum(PayBook.money).label('money')),
        peroid=peroid,
        item=PayBookItem.OUGHT_PAY
    ).group_by(
        PayBook.bankcard_id
    ).having(
        func.sum(PayBook.money) > 0.001
    ).all()

    bank_item = PayBookItem.query.filter(
        PayBookItem.name == PayBookItem.BANK).one()
    for paybook in paybooks:
        db.session.add_all(paybook.forward_tuple(
            bank_item, paybook.bankcard, current_user))
    db.session.commit()
    _operationlog(peroid=peroid)
    return SUCCESS


@app.route(
    '/paybook/fail?peroid=<peroid>&bankcard=<bankcard>&is_inter=<isinter>',
    methods=['GET', 'POST']
)
def paybook_fail_reg(peroid, bankcard, isinter):
    try:
        record = _paybook_query(
            db.session.query(
                PayBook.person,
                PayBook.bankcard,
                func.sum(PayBook.money).label('money')),
            bankcard=bankcard,
            peroid=peroid).group_by(PayBook.bankcard_id).one()
    except NoResultFound:
        to_404_page(
            error=unicode(
                'no paybook find in peroid:{} with bankcard:{}'
            ).format(peroid, bankcard))
    if request.method == 'GET':
        return render_template(
            'paybook_fail_reg.html',
            money=record.money,
            peroid=peroid,
            bankcard=bankcard)
    try:
        fail_money = float(request.form['money'])
    except ValueError:
        return redirect(request.url)
    if fail_money > record.money:
        to_500_page(
            back_url=request.url,
            error=unicode(
                'the fail money:{} is bigger than {}'
            ).format(fail_money, record.money))
    if isinter == 'True':
        from_item_name, to_item_name = (
            PayBookItem.INTER_BANK, PayBookItem.INTER_BANK_FAIL)

    else:
        from_item_name, to_item_name = (
            PayBookItem.BANK, PayBookItem.BANK_FAIL)
    from_item, to_item = [
        PayBookItem.query.filter(PayBookItem.name == name).one()
        for name in (from_item_name, to_item_name)]
    db.session.add_all(
        PayBook.remend_tuple(
            record.person, from_item, to_item, record.bankcard,
            fail_money, datetime.strptime(peroid, '%Y%m'), current_user
        )
    )
    db.session.commit()
    return SUCCESS


DEFAULT_ROLES = (
    ADMIN, ACCOUNTANT_ADMIN, ACCOUNTANT, BANKCARD_ADMIN, PERSON_ADMIN) = (
        'admin', 'accountant_admin', 'accountant', 'bankcard_admin',
        'person_admin')


# TODO add paybooks, add_validates, add notices,
# TODO add bankcard rename
def init_app(port=5000):
    try:
        admin = User.query.filter(User.name == 'admin').one()
    except NoResultFound:
        admin = User(name='admin')
        admin.password = 'admin'
        admin.roles.extend([Role(name=name) for name in DEFAULT_ROLES])
        try:
            address = Address.query.filter(
                Address.name == unicode('远安县')).one()
        except NoResultFound:
            address = Address(name=unicode('远安县'), no=unicode('42052511'))
        admin.address = address
        db.session.add(admin)

        pay_item = PayBookItem(name=PayBookItem.PAY, direct=-1)
        db.session.add(pay_item)
        for name in (PayBookItem.BANK, PayBookItem.INTER_BANK,
                     PayBookItem.OUGHT_PAY):
            db.seesion.add(
                PayBook(
                    name=name, direct=pay_item.direct, parent=pay_item))

        income_item = PayBookItem(name=PayBookItem.INCOME, direct=1)
        db.session.add(income_item)
        for name in (PayBookItem.BANK_FAIL, PayBookItem.INTER_BANK_FAIL,
                     PayBookItem.REMEND, PayBookItem.SYS):
            db.session.add(
                PayBookItem(
                    name=name, direct=income_item.direct, parent=income_item))
    db.session.commit()
