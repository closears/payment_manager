# coding=utf-8
import io
import csv
import codecs
import re
from zipfile import ZipFile
from functools import wraps
from collections import namedtuple
from datetime import datetime, date
from sqlalchemy import exists, and_, or_, false, func
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from werkzeug.routing import BaseConverter
from werkzeug.datastructures import MultiDict
import flask
from flask import (
    render_template, session, request, flash, abort, redirect, current_app,
    url_for, Response)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user)
from flask_principal import (
    Principal, Permission, Need, UserNeed, RoleNeed, identity_loaded,
    identity_changed, Identity)
from models import (
    app, db, paginate, User, Role, Address, Person, OperationLog,
    PersonStatusError, PersonAgeError, Standard, Bankcard, Note, PayBookItem,
    PayBook)
from flask_wtf.csrf import CsrfProtect
from forms import (
    Form, LoginForm, ChangePasswordForm, UserForm, AdminAddRoleForm,
    AdminRemoveRoleForm, RoleForm, PeroidForm, AddressForm, PersonForm,
    DateForm, StandardForm, StandardBindForm, BankcardForm, BankcardBindForm,
    NoteForm, PayItemForm, AmendForm, BatchSuccessFrom, FailCorrectForm,
    SuccessCorrectForm, AdminUserBindaddrForm)


def __find_obj_or_404(cls, id_field, pk):
    try:
        obj = db.session.query(cls).filter(id_field == pk).one()
    except NoResultFound:
        flash(unicode('Object witt pk:{} was not find').format(pk))
        abort(404)
    return obj


db.my_get_obj_or_404 = __find_obj_or_404


class RegexConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex = args[0]


class DateConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex = r'\d{4}-\d{2}-\d{2}'

    @classmethod
    def to_python(cls, value):
        return value and datetime.strptime(value, '%Y-%m-%d').date()

    @classmethod
    def to_url(cls, value):
        return value.strftime('%Y-%m-%d')\
            if isinstance(value, (datetime, date)) else value


class DateTimeConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex = r'\d{4}-\d{2}-\d{2}'

    @classmethod
    def to_python(cls, value):
        return value and datetime.strptime(value, '%Y-%m-%d')

    @classmethod
    def to_url(cls, value):
        return value.strftime('%Y-%m-%d') if isinstance(
            value, (datetime, date)) else value


class NoneConverter(BaseConverter):

    @classmethod
    def to_python(cls, value):
        return None if value == 'None' else value

    @classmethod
    def to_url(cls, value):
        return str(value)


class BooleanConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex == 'yes|no'

    @classmethod
    def to_python(cls, value):
        return value in ('yes', 'True', 'true', 'on')

    @classmethod
    def to_url(cls, value):
        return value and 'yes' or 'no'


app.url_map.converters['regex'] = RegexConverter
app.url_map.converters['date'] = DateConverter
app.url_map.converters['datetime'] = DateTimeConverter
app.url_map.converters['none'] = NoneConverter
app.url_map.converters['boolean'] = BooleanConverter

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

CsrfProtect(app)
Principal(app)
admin_required = Permission(RoleNeed('admin')).require(403)
person_admin_required = Permission(RoleNeed('person_admin')).require(403)
pay_admin_required = Permission(RoleNeed('pay_admin')).require(403)


def person_addr_filter(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        address_ids = map(
            lambda a: a.id,
            current_user.address and current_user.address.descendants or [])
        address_ids.append(current_user.address_id)
        old_person_query, old_bankcard_query\
            = Person.query, Bankcard.query
        Person.query = Person.query.filter(
            Person.address_id.in_(address_ids))
        Bankcard.query = Bankcard.query.filter(or_(
            Bankcard.owner_id.is_(None),
            exists().where(and_(
                Bankcard.owner_id == Person.id,
                Person.address_id.in_(address_ids)))))
        result = f(*args, **kwargs)
        Bankcard.query = old_bankcard_query
        Person.query = old_person_query
        return result
    return wrapper


@login_manager.user_loader
def load_user(userid):
    try:
        user = User.query.filter(User.id == userid).one()
    except NoResultFound:
        user = {
            'is_authenticated': (lambda: False),
            'is_active': (lambda: False),
            'is_anonymous': (lambda: True),
            'get_id': (lambda: None)}
    return user


class AddressAccessPermission(Permission):
    def __init__(self, address_id):
        super(AddressAccessPermission, self).__init__(
            Need(method='access', value=address_id))


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'roles') and current_user.roles:
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))
    if hasattr(current_user, 'address') and current_user.address:
        ids = [address.id for address in current_user.address.descendants]
        ids.append(current_user.address.id)
        for id in ids:
            identity.provides.add(AddressAccessPermission(id))


@app.errorhandler(404)
def page_not_found(error):
    session.get('back_url', None) or session.update(back_url=url_for('index'))
    return render_template('404.html'), 404


@app.errorhandler(500)
def page_error(error):
    try:
        session.get('back_url', None) or session.update(
            back_url=url_for('index'))
    except Exception:
        pass
    return render_template('500.html'), 500


@app.errorhandler(403)
def page_forbiden(error):
    try:
        session.get('back_url', None) or session.update(
            back_url=url_for('index'))
    except Exception:
        pass
    return render_template('403.html'), 403


@app.before_request
def before_request():
    session['error'] = None
    if request.method == 'POST':
        method = request.form.get('_method', '').upper()
        if method:
            request.environ['REQUEST_METHOD'] = method
            ctx = flask._request_ctx_stack.top
            ctx.url_adapter.default_method = method
            assert request.method == method


@app.template_global(name='reduce')
def _reduce():
    return reduce


@app.template_global(name='map')
def _map():
    return map


@app.template_global()
def lst2csv(lst):
    return reduce(lambda x, y: '{},{}'.format(x, y), lst) if lst else ''


@app.template_global()
def url_for_other_page(page, per_page):
    args = request.view_args.copy()
    args.update(**request.args)
    args['page'] = page,
    args['per_page'] = per_page
    return url_for(request.endpoint, **args)


@app.route('/success', methods=['GET'])
def success():
    '''just for test'''
    return render_template('success.html')


@app.route('/', methods=['GET'])
@login_required
def main_page():
    return render_template('index.html')


@app.route('/index.html', methods=['GET'])
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@OperationLog.log_template()
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        token = User()
        form.populate_obj(token)
        redirect_url = '/login?next={}'.format(
            request.args.get('next') or url_for('index'))
        try:
            user = User.query.filter(User.name == token.name).one()
            if token != user:
                return redirect(redirect_url)
        except NoResultFound:
            return redirect(redirect_url)
        login_user(user)
        identity_changed.send(
            current_app._get_current_object(),
            identity=Identity(user.id))
        OperationLog.log(db.session, current_user)
        return redirect(request.args.get('next') or url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET'])
@login_required
@OperationLog.log_template()
def logout():
    OperationLog.log(db.session, current_user)
    logout_user()
    return redirect(url_for('login'))


@app.route('/user/changepassword', methods=['GET', 'POST'])
@login_required
@OperationLog.log_template()
def user_changepassword():
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter(User.id == current_user.id).one()
        if User(password=form.oldpassword.data).password != user.password:
            logout_user()
            return redirect('/login')
        form.populate_obj(user)
        OperationLog.log(db.session, current_user)
        db.session.commit()
        identity_changed.send(
            current_app._get_current_object(),
            identity=Identity(user.id))
        return 'success'
    return render_template('changepassword.html', form=form)


@app.route('/admin/user/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }}')
def admin_add_user():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        user = User()
        form.populate_obj(user)
        db.session.add(user)
        db.session.commit()
        OperationLog.log(db.session, current_user, user=user)
        db.session.commit()
        return 'success'
    return render_template('/admin_add_user.html', form=form)


@app.route('/admin/user/<int:pk>/remove', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.name }}')
def admin_remove_user(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash(unicode('no user find with pk:{}').format(pk))
        abort(404)
    form = Form(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        OperationLog.log(db.session, current_user, user=user)
        db.session.delete(user)
        db.session.commit()
        return 'success'
    return render_template(
        'confirm.html', form=form, title='delete user', message=(
            'confirm delete the user:{}').format(user.name))


@app.route('/admin/user/<int:pk>/inactivate', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }}')
def admin_user_inactivate(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash(unicode('no user find with pk:{}').format(pk))
        abort(404)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
            OperationLog.log(db.session, current_user, user=user)
            user.active = False
            db.session.commit()
            return 'success'
    return render_template(
        'confirm.html', form=form, title='user inactivate', message=unicode(
            'user deactivate: {}').format(user.name))


@app.route('/admin/user/<int:pk>/activate', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }}')
def admin_user_activate(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash(unicode('no user find with pk:{}').format(pk))
        abort(404)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
            user.active = True
            OperationLog.log(db.session, current_user, user=user)
            db.session.commit()
            return 'success'
    return render_template(
        'confirm.html', form=form, title='user activate', message=unicode(
            'activate user:{}').format(user.name))


@app.route(
    '/admin/user/<int:pk>/changepassword', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }}')
def admin_user_changepassword(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash('no user find by pk:{}'.format(pk))
        abort(404)
    init_data = MultiDict()
    init_data.update(request.form)
    init_data.update({'oldpassword': 'empty'})
    form = ChangePasswordForm(init_data)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(user)
        OperationLog.log(db.session, current_user, user=user)
        db.session.commit()
        return 'success'
    return render_template('admin_user_changepassword.html', form=form)


@app.route(
    '/admin/user/<int:pk>/addrole', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }},added_role:{{ form.role.data }}')
def admin_user_add_role(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash('no user find with pk:{}'.format(pk))
        abort(404)
    form = AdminAddRoleForm(user, formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(user)
        OperationLog.log(db.session, current_user, user=user, form=form)
        db.session.commit()
        identity_changed.send(
            current_app._get_current_object(),
            identity=Identity(user.id))
        return 'success'
    return render_template('admin_user_add_role.html', form=form, user=user)


@app.route(
    '/admin/user/<int:pk>/removerole', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }},removed_roles:{{ form.role.data }}')
def admin_user_remove_role(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash('no user find with pk:{}'.format(pk))
        abort(404)
    form = AdminRemoveRoleForm(user, formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(user)
        OperationLog.log(db.session, current_user, user=user, form=form)
        db.session.commit()
        return 'success'
    return render_template('admin_user_remove_role.html', form=form, user=user)


@app.route('/admin/user/<int:pk>/bindaddr', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ address_id }}')
def admin_user_bindaddr(pk):
    user = db.my_get_obj_or_404(User, User.id, pk)
    form = AdminUserBindaddrForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        user.address_id = form.address.data
        OperationLog.log(db.session, current_user, address_id=user.address_id)
        db.session.commit()
        return 'success'
    return render_template('admin_user_bindaddr.html', form=form)


@app.route('/admin/user/<int:pk>/detail', methods=['GET'])
@admin_required
def admin_user_detail(pk):
    user = db.my_get_obj_or_404(User, User.id, pk)
    return render_template('admin_user_detail.html', user=user)


@app.route(
    '/admin/user/page/<int:page>/perpage/<int:per_page>/search',
    methods=['GET']
)
@admin_required
def admin_user_search(page, per_page):
    name = request.args.get('name')
    if name:
        query = User.query.filter(
            User.name.like('{}%'.decode('utf-8').format(name)))
    else:
        query = User.query
    return render_template(
        'admin_user_search.html', pagination=query.paginate(page, per_page))


@app.route('/admin/role/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ role.id }}')
def admin_role_add():
    form = RoleForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        role = Role()
        form.populate_obj(role)
        db.session.add(role)
        db.session.commit()
        OperationLog.log(db.session, current_user, role=role)
        db.session.commit()
        return 'success'
    return render_template('admin_role_add.html', form=form)


@app.route('/admin/role/<int:pk>/romve', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ role.name }}')
def admin_role_remove(pk):
    try:
        role = Role.query.filter(Role.id == pk).one()
    except NoResultFound:
        flash('The Role with pi{} was not find!'.format(pk))
        abort(404)
    form = Form(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        for user in role.users:
            user.roles = filter(lambda r: r.id != role.id, user.roles)
            db.session.commit()
        db.session.delete(role)
        db.session.commit()
        return 'success'
    return render_template(
        'confirm.html', form=form, title='role remove', message=unicode(
            'confirm delete the role:{}').format(role.name))


@app.route('/role/page/<int:page>/perpage/<int:per_page>/search',
           methods=['GET'])
@admin_required
def admin_role_search(page, per_page):
    name = request.args.get('name')
    query = Role.query
    if name:
        query = query.filter(
            Role.name.like('{}%'.decode('utf-8').format(name)))
    return render_template('role_search.html',
                           pagination=query.paginate(page, per_page))


@app.route(
    '/admin/log/page/<int:page>/per_page/<int:per_page>/search',
    methods=['GET'])
@admin_required
def admin_log_search(page, per_page):
    operator_name = request.args.get('operator_name')
    start_date, end_date = map(
        lambda x: (lambda y: y and datetime.strptime(y, '%Y-%m-%d').date())(
            request.args.get(x)),
        ('start_date', 'end_date'))
    query = OperationLog.query
    if operator_name:
        query = OperationLog.query.filter(
            exists().where(and_(
                OperationLog.operator_id == User.id,
                User.name == operator_name)))
    if start_date:
        query = query.filter(
            OperationLog.time >= start_date)
    if end_date:
        query = query.filter(
            OperationLog.time <= end_date)
    pagination = query.paginate(page, per_page)
    return render_template('admin_log_search.html', pagination=pagination)


@app.route(
    '/admin/log/operator_id/<int:operator_id>/clean', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template()
def admin_log_clean(operator_id):
    try:
        user = User.query.filter(User.id == operator_id).one()
    except NoResultFound:
        flash('No user was find by pk:{}'.format(operator_id))
        abort(404)
    form = PeroidForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        query = OperationLog.query.filter(
            OperationLog.operator_id == operator_id)
        if form.start_date.data:
            start_time = datetime.fromordinal(form.start_date.data.toordinal())
            query = query.filter(OperationLog.time >= start_time)
        if form.end_date.data:
            end_time = datetime.fromordinal(form.end_date.data.toordinal())
            query = query.filter(OperationLog.time <= end_time)
        query.delete()
        db.session.commit()
        return 'success'
    return render_template('admin_log_clean.html', form=form, user=user)


@app.route('/address/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ address.id }}')
def address_add():
    form = AddressForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        address = Address()
        form.populate_obj(address)
        db.session.add(address)
        db.session.commit()
        OperationLog.log(db.session, current_user, address=address)
        db.session.commit()
        return 'success'
    return render_template('address_edit.html', form=form)


@app.route('/address/<int:pk>/delete', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ address.name }}')
def address_delete(pk):
    try:
        address = Address.query.filter(Address.id == pk).one()
    except NoResultFound:
        flash(unicode('Address with pk:{} not find').format(pk))
        abort(404)
    form = Form(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        for descendant in address.descendants:
            db.session.delete(descendant)
            OperationLog.log(db.session, current_user, address=descendant)
        db.session.delete(address)
        OperationLog.log(db.session, current_user, address=address)
        db.session.commit()
        return 'success'
    return render_template(
        'confirm.html', form=form, title='delete address', message=unicode(
            'confirm delete the :{}? It will delete all childs of it!'
        ).format(address.name))


@app.route('/address/<int:pk>/edit', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template()
def address_edit(pk):
    try:
        address = Address.query.filter(Address.id == pk).one()
    except NoResultFound:
        flash(unicode('No address fiind by pk:{}'.format(pk)))
        abort(404)
    form = AddressForm(formdata=request.form, obj=address)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(address)
        db.session.commit()
        return 'success'
    return render_template('address_edit.html', form=form)


@app.route(
    '/address/page/<int:page>/perpage/<int:per_page>/search',
    methods=['GET'])
@login_required
def address_search(page, per_page):
    name = (lambda x: x != 'None' and x or None)(request.args.get('name'))
    query = Address.query
    if current_user.address:
        address_ids = map(lambda a: a.id, current_user.address.descendants)
        address_ids.append(current_user.address.id)
        query = query.filter(Address.id.in_(address_ids))
    else:
        query = query.filter(false())
    if name:
        query = query.filter(
            Address.name.like('{}%'.decode('utf-8').format(name)))
    return render_template(
        'address_search.html', pagination=query.paginate(page, per_page))


@app.route('/person/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ person.id }},')
def person_add():
    form = PersonForm(current_user, formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        person = Person()
        try:
            form.populate_obj(person)
        except (PersonStatusError, PersonAgeError):
            flash('person aready registed')
            db.session.rollback()
            abort(500)
        db.session.add(person)
        db.session.commit()
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('person_edit.html', form=form)


@app.route('/person/upload', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template()
def person_upload():
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        f = request.files.get('file')
        if f.read(len(codecs.BOM_UTF8)) != codecs.BOM_UTF8:
            f.seek(0)
        persons = []
        Reader = namedtuple(
            'Reader', 'idcard,name,address_no,address_detail,securi_no')

        def idcard2birthday(idcard):
            return datetime.strptime(idcard[6:14], '%Y%m%d').date()
        for no, fields in enumerate(csv.reader(f)):
            record = Reader._make(fields)
            if not (re.match(r'^\d{17}[\d|X]$', record.idcard)
                    and re.match(r'^[\w\W]+[号|组]$', record.address_detail)):
                flash(('Syntax error in upload file at line:{},' +
                       ' content:{}').format(no, fields))
                abort(500)
            # fields = map(lambda x: x.decode('utf-8'), fields)
            address = db.my_get_obj_or_404(
                Address, Address.no, record.address_no)
            persons.append(
                Person(
                    idcard=record.idcard,
                    birthday=idcard2birthday(record.idcard),
                    name=record.name,
                    address=address,
                    address_detail=record.address_detail,
                    securi_no=record.securi_no,
                    personal_wage=0,
                    create_by=current_user
                ).reg())
        OperationLog.log(db.session, current_user)
        db.session.add_all(persons)
        db.session.commit()
        return 'success'
    return render_template('upload.html', form=form)


@app.route('/person/<int:pk>/delete', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},{{ person.idcard }}')
def person_delete(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = Form(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        OperationLog.log(db.session, current_user, person=person)
        db.session.delete(person)
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='person delete',
                           message=unicode('Confirm delete person:{}?').format(
                               person.idcard))


@app.route('/person/<int:pk>/retire_reg', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},')
def person_retire_reg(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = DateForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person.retire(form.date.data)
        except (PersonStatusError, PersonAgeError):
            flash('Person can not be retire')
            db.session.rollback()
            abort(500)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('date.html', form=form, title='persn retire reg')


@app.route('/person/<int:pk>/normal_reg', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},')
def person_normal_reg(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person.normal()
        except (PersonStatusError, PersonAgeError):
            flash('Person can not normal')
            db.session.rollback()
            abort(500)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='normal reg')


@app.route('/person/batch_normal', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},')
def person_batch_normal():
    form = PeroidForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        persons = db.session.query(Person).filter(
            Person.can_normal.is_(True)).filter(
                Person.birthday >= form.start_date.data).filter(
                    Person.birthday <= form.end_date.data).all()
        for person in persons:
            person.normal()
            OperationLog.log(db.session, current_user, person=person)
        db.session.flush()
        db.session.commit()
        return 'succes'
    return render_template('person_batch_normal.html', form=form)


@app.route('/person/<int:pk>/dead_reg', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},')
def person_dead_reg(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = DateForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person.dead(form.date.data)
        except (PersonAgeError, PersonStatusError):
            flash('Person can not dead')
            db.session.rollback()
            abort(500)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('date.html', form=form, title='dead reg')


@app.route('/person/<int:pk>/abort_reg', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},')
def person_abort_reg(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person.abort()
        except (PersonAgeError, PersonStatusError):
            flash('Person can not abort')
            db.session.rollback()
            abort(500)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='persn abort')


@app.route('/person/<int:pk>/suspend', methods=['GET', 'POST'])
@person_admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }}')
def person_suspend_reg(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person.suspend()
        except (PersonAgeError, PersonStatusError):
            flash('Person can not suspend')
            db.session.rollback()
            abort(500)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='person suspend')


@app.route('/person/<int:pk>/resume', methods=['GET', 'POST'])
@person_admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},')
def person_resume_reg(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person.resume()
        except (PersonAgeError, PersonStatusError):
            flash('Person can not resume')
            db.session.rollback()
            abort(500)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='person resume')


@app.route('/person/<int:pk>/update', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{person.id }},{{ person.idcard }},' +
                           '{{ person.name }},{{ person.idcard }},')
def person_update(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = PersonForm(current_user, obj=person, formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        OperationLog.log(db.session, current_user, person=person)
        form.populate_obj(person)
        db.session.commit()
        return 'success'
    return render_template('person_edit.html', form=form)


@app.route('/person/<int:pk>/detail', methods=['GET'])
@login_required
@person_addr_filter
def person_detail(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    return render_template('person_detail.html', person=person)


@app.route('/person/page/<int:page>/perpage/<int:per_page>/search',
           methods=['GET'])
@login_required
@person_addr_filter
def person_search(page, per_page):
    idcard, name, address = map(
        lambda x: request.args.get(x), ('idcard', 'name', 'address'))
    query = Person.query
    if idcard:
        query = query.filter(
            Person.idcard.like('{}%'.decode('utf-8').format(idcard)))
    if name:
        query = query.filter(
            Person.name.like('{}%'.decode('utf-8').format(name)))
    if address:
        stmt = exists().where(and_(
            Person.address_id == Address.id,
            Address.name.like('{}%'.decode('utf-8').format(address))))
        query = query.filter(stmt)
    return render_template('person_search.html',
                           pagination=query.paginate(page, per_page))


@app.route('/person/<int:pk>/standardbind', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }},{{ form.standard_id.data }}')
def standard_bind(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = StandardBindForm(person, formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(person)
        if not person.is_valid_standard_wages:
            db.session.rollback()
            flash("person's standard wages were conflict")
            abort(500)
        OperationLog.log(db.session, current_user, person=person, form=form)
        db.session.commit()
        return 'success'
    return render_template('standard_bind.html', form=form)


@app.route('/person/<int:pk>/page/<int:page>/perpage/<int:per_page>/search',
           methods=['GET'])
@login_required
def person_log_search(pk, page, per_page):
    start_date, end_date = map(
        lambda x: request.args.get(x),
        ('start_date', 'end_date'))
    start_date, end_date = map(
        lambda x: x and datetime.strptime(x, '%Y-%m-%d').date(),
        (start_date, end_date))
    operator_id = request.args.get('operator_id')
    query = OperationLog.query.filter(
        OperationLog.method.in_([m.__name__ for m in (
            person_abort_reg,
            person_add,
            person_batch_normal,
            person_dead_reg,
            person_delete,
            person_normal_reg,
            person_retire_reg,
            person_resume_reg,
            person_suspend_reg,
            person_update)]))
    if pk:
        query = query.filter(OperationLog.remark.like('{},%'.format(pk)))
    if start_date:
        query = query.filter(OperationLog.time >= start_date)
    if end_date:
        query = query.filter(OperationLog.time <= end_date)
    if operator_id:
        query = query.filter(OperationLog.operator_id == operator_id)
    return render_template('person_log_search.html',
                           pagination=query.paginate(page, per_page))


@app.route('/standard/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ standard.id }}')
def standard_add():
    form = StandardForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        standard = Standard()
        form.populate_obj(standard)
        db.session.add(standard)
        db.session.commit()
        OperationLog.log(db.session, current_user, standard=standard)
        db.session.commit()
        return 'success'
    return render_template('standard_edit.html', form=form)


@app.route('/bankcard/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ bankcard.id }}')
def bankcard_add():
    form = BankcardForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        bankcard = Bankcard()
        form.populate_obj(bankcard)
        bankcard.create_by = current_user
        db.session.commit()
        OperationLog.log(db.session, current_user, bankcard=bankcard)
        db.session.commit()
        return 'success'
    return render_template('bankcard_edit.html', form=form)


@app.route('/bankcard/<int:pk>/bind/', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ bankcard.id }},{{ bankcard.owner.idcard }}')
def bankcard_bind(pk):
    bankcard = db.my_get_obj_or_404(Bankcard, Bankcard.id, pk)
    form = BankcardBindForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            person = Person.query.filter(
                Person.idcard == form.idcard.data).one()
        except NoResultFound:
            flash(unicode('no person find by idcard:{}').format(
                form.idcard.data))
            abort(404)
        except MultipleResultsFound:
            flash(unicode('the condition({}) is too blurred').format(
                form.idcard.data))
            abort(500)
        bankcard.owner_id = person.id
        OperationLog.log(db.session, current_user, bankcard=bankcard)
        db.session.commit()
        return 'success'
    return render_template('bankcard_bind.html', form=form)


@app.route('/bankcard/<int:pk>/update', methods=['GET', 'POST'])
@admin_required
@person_addr_filter
@OperationLog.log_template('{{ bankcard.id }}')
def bankcard_update(pk):
    bankcard = db.my_get_obj_or_404(Bankcard, Bankcard.id, pk)
    form = BankcardForm(formdata=request.form, obj=bankcard)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(bankcard)
        OperationLog.log(db.session, current_user, bankcard=bankcard)
        db.session.commit()
        return 'success'
    return render_template('bankcard_edit.html', form=form)


@app.route('/bankcard/page/<int:page>/perpage/<int:per_page>/search',
           methods=['GET'])
@person_addr_filter
@login_required
def bankcard_search(page, per_page):
    no, name, idcard = map(
        lambda x: (lambda y: y != 'None' and y or None)(request.args.get(x)),
        ('no', 'name', 'idcard'))
    query = Bankcard.query
    if no:
        query = query.filter(
            Bankcard.no.like('{}%'.decode('utf-8').format(no)))
    if name:
        query = query.filter(
            Bankcard.name.like('{}%'.decode('utf-8').format(name)))
    if idcard:
        stmt = exists().where(and_(
                              Bankcard.owner_id == Person.id,
                              Person.idcard.like(
                                  '{}%'.decode('utf-8').format(idcard))))
        query = query.filter(stmt)
    return render_template('bankcard_search.html',
                           pagination=query.paginate(page, per_page))


@app.route('/note/add', methods=['GET', 'POST'])
@login_required
@OperationLog.log_template()
def note_add():
    form = NoteForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        note = Note()
        form.populate_obj(note)
        note.user = current_user
        db.session.add(note)
        db.session.commit()
        return 'success'
    return render_template('note_edit.html', form=form)


@app.route('/note/forperson/<int:pk>', methods=['GET', 'POST'])
@person_admin_required
@person_addr_filter
@OperationLog.log_template('{{ person.id }}')
def note_add_to_person(pk):
    person = db.my_get_obj_or_404(Person, Person.id, pk)
    form = NoteForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        note = Note()
        form.populate_obj(note)
        note.person = person
        db.session.add(note)
        OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'success'
    return render_template('note_edit.html', form=form,
                           title='note add')


def _get_note_or_404(pk):
    try:
        note = Note.query.filter(Note.id == pk).filter(
            Note.user_id == current_user.id).one()
    except NoResultFound:
        flash('note not find')
        abort(404)
    return note


@app.route('/note/finish/<int:pk>', methods=['GET', 'POST'])
@login_required
@OperationLog.log_template()
def note_finish(pk):
    note = _get_note_or_404(pk)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        note.finish()
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='note_finish')


@app.route('/note/disable/<int:pk>', methods=['GET', 'POST'])
@login_required
@OperationLog.log_template()
def note_disable(pk):
    note = _get_note_or_404(pk)
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        note.disable()
        db.session.commit()
        return 'success'
    return render_template('confirm.html', form=form, title='note_finish')


@app.route('/note/clean', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template()
def note_clean():
    form = DateForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        Note.query.filter(Note.start_date <= form.date.data).filter(
            Note.effective.is_(True)).delete()
        db.session.commit()
        return 'success'
    return render_template('date.html', form=form,
                           title='clean before {}'.format(form.date.data))


@app.route('/note/page/<int:page>/per_page/<int:per_page>/search',
           methods=['GET'])
@login_required
def note_search(page, per_page):
    finished = BooleanConverter.to_python(request.args.get('finished'))
    query = Note.query.filter(Note.effective.is_(True)).filter(
        Note.finished == finished)
    if not current_user.has_role('admin'):
        query = query.filter(Note.user_id == current_user.id)
    return render_template('note_search.html', pagination=query.paginate(
        page, per_page))


@app.route('/note/touser/<int:user_id>', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user_id }}')
def note_to_user(user_id):
    user = db.my_get_obj_or_404(User, User.id, user_id)
    form = NoteForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        note = Note()
        form.populate_obj(note)
        note.user = user
        db.session.commit()
        return 'success'
    return render_template('note_edit.html', form=form,
                           title='notice to person')


@app.route('/payitem/add', methods=['GET', 'POST'])
@pay_admin_required
@OperationLog.log_template('{{ item.id }}')
def payitem_add():
    form = PayItemForm(formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        item = PayBookItem()
        form.populate_obj(item)
        db.session.add(item)
        db.session.commit()
        OperationLog.log(db.session, current_user, item=item)
        return 'success'
    return render_template('payitem_edit.html', form=form,
                           title='payitem add')


@app.route('/payitem/<int:pk>/detail', methods=['GET'])
@pay_admin_required
def pay_item_detail(pk):
    item = db.my_get_obj_or_404(PayBookItem, PayBookItem.id, pk)
    return render_template('pay_item_detail.html', item=item)


@app.route('/payitem/page/<int:page>/perpage/<int:per_page>/search',
           methods=['GET'])
@pay_admin_required
def pay_item_search(page, per_page):
    name = request.args.get('name')
    query = PayBookItem.query
    if name:
        query = query.filter(
            PayBookItem.name.like('{}%'.decode('utf-8').format(name)))
    return render_template('pay_item_search.html',
                           pagination=query.paginate(page, per_page))


@app.route('/paybook/upload', methods=['GET', 'POST'])
@pay_admin_required
@OperationLog.log_template('{{ peroid }}')
def paybook_upload():
    peroid = request.args.get('peroid')
    if peroid:
        peroid = datetime.strptime(peroid, '%Y-%m-%d').date()
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        f = request.files['file']
        if f.read(len(codecs.BOM_UTF8)) != codecs.BOM_UTF8:
            f.seek(0)
        Reader = namedtuple('Reader',
                            'securi_no,name,idcard,money,village_no,bankcard')

        def validate(record):
            if not re.match(r'^(?:(?:\d{19})|(?:\d{2}-\d{15}))[\w\W]*$',
                            record.bankcard):
                return False
            if not re.match(r'^\d{17}[\d|X]$', record.idcard):
                return False
            if not re.match(r'^\d+(?:\.\d{2})?$', record.money):
                return False
            return True
        for line_no, line in enumerate(f):
            line = line.replace('|', ',').rstrip(',')
            fields = map(lambda x: x.decode('utf-8'),
                         csv.reader([line]).next())
            record = Reader._make(fields)
            if not validate(record):
                flash('Syntx error in line:{}'.format(line_no))
                abort(500)
            item1 = PayBookItem.query.filter(
                PayBookItem.name == 'sys_should_pay').one()
            item2 = PayBookItem.query.filter(
                PayBookItem.name == 'bank_should_pay').one()
            try:
                bankcard_no = re.match(r'^((?:\d{19})|(?:\d{2}-\d{15}))' +
                                       '[\w\W]*$', record.bankcard).group(1)
                bankcard = Bankcard.query.filter(
                    Bankcard.no == bankcard_no).one()
                person = Person.query.filter(
                    Person.idcard == record.idcard).one()
            except NoResultFound:
                flash('Bankcard or person not find. In line:{}'.format(
                    line_no))
                abort(500)
            if not bankcard.binded:
                flash("unbind bankcard can't pay")
                abort(500)
            db.session.add_all(PayBook.create_tuple(
                person, item1.id, item2.id, bankcard, bankcard,
                float(record.money),
                peroid, current_user.id))
        OperationLog.log(db.session, current_user, peroid=peroid)
        db.session.commit()
        return 'success'
    return render_template('upload.html', form=form)


@app.route('/paybook/person/<int:person_id>/amend', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ person_id }},{{ peroid }}')
def paybook_amend(person_id):
    peroid = request.args.get('peroid')
    if not peroid:
        flash("the peroid is required")
        abort(500)
    peroid = datetime.strptime(peroid, '%Y-%m-%d').date()
    money = func.sum(PayBook.money).label('money')
    paybooks = db.session.query(
        PayBook.person_id.label('person'),
        PayBook.bankcard_id.label('bankcard'),
        PayBook.item_id.label('item'),
        PayBook.peroid,
        money).filter(
            PayBook.item_is('sys_should_pay'),
            PayBook.person_id == person_id,
            PayBook.in_peroid(peroid)).group_by(
                PayBook.bankcard_id).having(money < 0).all()
    form = AmendForm(obj=paybooks, user=current_user, formdata=request.form)
    payed = db.session.query(money).filter(
        PayBook.in_peroid(peroid),
        PayBook.item_is('bank_should_pay')).scalar() == 0
    if not payed and request.method == 'POST' and form.validate_on_submit():
        lst = []
        try:
            form.populate_obj(lst)
        except NoResultFound:
            abort(404)
        db.session.add_all(lst)
        OperationLog.log(db.session, current_user, person_id=person_id,
                         peroid=peroid)
        db.session.commit()
        return 'success'
    return render_template('paybook_amend.html', form=form)


@app.route('/paybook/batchsuccess', methods=['GET', 'POST'])
@pay_admin_required
@OperationLog.log_template('{{ fails }}')
def paybook_batch_success():
    form = BatchSuccessFrom(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        money = func.sum(PayBook.money).label('money')
        query = db.session.query(
            PayBook.person_id,
            PayBook.bankcard_id,
            PayBook.peroid.label('peroid'),
            money).filter(
                PayBook.item_is('bank_should_pay'),
                PayBook.in_peroid(form.peroid.data)).group_by(
                    PayBook.bankcard_id).having(money > 0)
        in_fails = exists().where(and_(
            PayBook.bankcard_id == Bankcard.id,
            Bankcard.no.in_(form.fails.data.splitlines())))\
            if form.fails.data.splitlines() else false()
        bank_should, bank_payed, bank_failed = [PayBookItem.query.filter(
            PayBookItem.name == name).one() for name in
            ('bank_should_pay', 'bank_payed', 'bank_failed')]
        lst = []
        for book in query.filter(in_fails):
            lst.extend(PayBook.create_tuple(
                book.person_id, bank_should, bank_failed,
                book.bankcard_id, book.bankcard_id,
                book.money, book.peroid, current_user))
        for book in query.filter(~in_fails):
            lst.extend(PayBook.create_tuple(
                book.person_id, bank_should, bank_payed,
                book.bankcard_id, book.bankcard_id,
                book.money, book.peroid, current_user))
        db.session.add_all(lst)
        OperationLog.log(db.session, current_user,
                         fails=','.join(form.fails.data.splitlines()))
        db.session.commit()
        return 'success'
    return render_template('paybook_batch_success.html', form=form)


@app.route('/paybook/person/<int:person_id>' +
           '/peroid/<date:peroid>/failcrrect',
           methods=['GET', 'POST'])
@pay_admin_required
@OperationLog.log_template('{{ person_id }},{{ peroid }}')
def paybook_fail_correct(person_id, peroid):
    form = FailCorrectForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        money_q = func.sum(PayBook.money).label('money')
        books = db.session.query(
            PayBook.bankcard_id.label('bankcard'),
            money_q).filter(
            PayBook.person_id == person_id,
            PayBook.item_is('bank_failed'),
            PayBook.in_peroid(peroid)).group_by(
                PayBook.bankcard_id).having(money_q > 0).all()
        bank_failed, bank_should = [
            PayBookItem.query.filter(
                PayBookItem.name == name).one()
            for name in ('bank_failed', 'bank_should_pay')]
        try:
            bankcard2 = Bankcard.query.filter(
                Bankcard.no == form.bankcard.data).one()
        except NoResultFound:
            flash('No bankcard find by no:{}. Please add it first.'.format(
                form.bankcard.data))
            abort(404)
        if not bankcard2.binded:
            flash('Bankcard with no:{} not binded, bind it first'.format(
                bankcard2.no))
            abort(500)
        # valish all money of paybook with failed bankcard
        # in bank failed item and
        # transfer to book record with new bankcard
        db.session.add_all(
            reduce(
                lambda lst, b: lst.extend(
                    PayBook.create_tuple(
                        person_id,
                        bank_failed,
                        bank_should,
                        b.bankcard,
                        bankcard2,
                        b.money,
                        datetime.now(),
                        current_user)) or lst,
                books, []))
        OperationLog.log(db.session, current_user, person_id=person_id,
                         peroid=peroid)
        db.session.commit()
        return 'success'
    return render_template('paybook_fail_correct.html', form=form)


@app.route('/paybook/bankcard/<int:bankcard_id>' +
           '/person/<int:person_id>' +
           '/peroid/<date:peroid>/successcorrect', methods=['GET', 'POST'])
@pay_admin_required
@OperationLog.log_template('{{ person_id }},{{ bankcard_id }},{{ peroid }}')
def paybook_success_correct(bankcard_id, person_id, peroid):
    form = SuccessCorrectForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        money = func.sum(PayBook.money).label('money')
        books = db.session.query(
            PayBook.person_id.label('person'),
            PayBook.bankcard_id.label('bankcard'),
            PayBook.peroid,
            money).filter(
                PayBook.item_is('bank_payed'),
                PayBook.in_peroid(peroid),
                PayBook.person_id == person_id,
                PayBook.bankcard_id == bankcard_id).group_by(
                    PayBook.person_id, PayBook.bankcard_id).having(
                        money > 0).all()
        bank_payed, bank_failed = [
            PayBookItem.query.filter(PayBookItem.name == name).one()
            for name in ('bank_payed', 'bank_failed')]
        if books:
            db.session.add_all(
                PayBook.create_tuple(
                    person_id,
                    bank_payed,
                    bank_failed,
                    bankcard_id,
                    bankcard_id,
                    min(form.money.data, books[0].money),
                    peroid,
                    current_user))
        OperationLog.log(db.session, current_user, person_id=person_id,
                         bankcard_id=bankcard_id, peroid=peroid)
        db.session.commit()
        return 'success'
    return render_template('paybook_success_correct.html', form=form)


def _paybook_query(person_idcard, item_names, peroid, negative=False):
    money = func.sum(PayBook.money).label('money')
    item = aliased(PayBookItem)
    query = db.session.query(
        PayBook.peroid,
        PayBook.person_id.label('person'),
        Person.idcard,
        Person.name.label('person_name'),
        PayBook.bankcard_id.label('bankcard'),
        Bankcard.no.label('bankcard_no'),
        Bankcard.name.label('bankcard_name'),
        item.name.label('item'),
        money).join(
            Person, Person.id == PayBook.person_id).join(
                Bankcard, Bankcard.id == PayBook.bankcard_id).join(
                    item, item.id == PayBook.item_id)
    if person_idcard:
        query = query.filter(Person.idcard == person_idcard)
    if item_names:
        query = query.filter(PayBook.item_in(item_names))
    if peroid:
        if isinstance(peroid, str):
            try:
                peroid = datetime.strptime(peroid, '%Y-%m-d').date()
            except ValueError:
                try:
                    peroid = datetime.strptime(peroid, '%Y%m').date()
                except ValueError:
                    peroid = None
        query = query.filter(PayBook.in_peroid(peroid))
    addr_ids = map(lambda a: a.id, current_user.address.descendants)
    addr_ids.append(current_user.address.id)
    query = query.filter(Person.address_id.in_(addr_ids))
    query = query.group_by(PayBook.bankcard_id, item.id, PayBook.peroid)
    if negative:
        query = query.having(money < 0)
    else:
        query = query.having(money > 0)
    return query


@app.route('/paybook/page/<int:page>/perpage/<int:per_page>/bank/search',
           methods=['GET'])
@login_required
def paybook_search(page, per_page):
    '''
    search bank pay book
    '''
    person_idcard, peroid = map(
        lambda name: request.args.get(name),
        ('person_idcard', 'peroid'))
    item_names = BooleanConverter.to_python(request.args.get('all'))\
        and ['bank_should_pay', 'bank_payed', 'bank_failed'] or ['bank_payed']
    query = _paybook_query(person_idcard, item_names, peroid)
    return render_template(
        'paybook_list.html',
        pagination=paginate(query, page, per_page))


@app.route('/paybook/page/<int:page>/perpage/<int:per_page>/sys/search',
           methods=['GET'])
@admin_required
def paybook_sys_search(page, per_page):
    '''
    search for sys pay book
    '''
    person_idcard, peroid = map(
        lambda name: request.args.get(name),
        ('person_idcard', 'peroid'))
    item_names = BooleanConverter.to_python(request.args.get('all')) and\
        ['sys_should_pay', 'sys_amend'] or\
        ['sys_should_pay']
    query = _paybook_query(person_idcard, item_names, peroid, negative=True)
    return render_template(
        'paybook_list.html',
        pagination=paginate(query, page, per_page))


@app.route('/paybook/bankgrant', methods=['GET'])
@pay_admin_required
@OperationLog.log_template()
def paybook_bankgrant():
    money = func.sum(PayBook.money).label('money')
    query = db.session.query(
        Person.idcard.label('idcard'),
        Bankcard.no.label('bankcard_no'),
        Bankcard.name.label('bankcard_name'),
        money,
        Person.status.label('remark')).join(
            PayBook, Person.id == PayBook.person_id).join(
                Bankcard, Bankcard.id == PayBook.bankcard_id).filter(
                    PayBook.item_is('bank_should_pay'))
    peroid = None
    if request.args.get('peroid'):
        peroid = DateConverter.to_python(request.args.get('peroid'))
    if peroid:
        query = query.filter(PayBook.in_peroid(peroid))
    books = query.group_by(
        PayBook.bankcard_id).having(
            money > 0).all()

    def book2csv(book):

        def make_no(idcard):
            return idcard[-1] == 'X' and idcard[8:-1] + '01'\
                or idcard[8:] + '0'
        return ','.join(
            map(
                lambda x: str(x),
                (
                    make_no(book.idcard),
                    book.bankcard_no,
                    book.bankcard_name,
                    book.money,
                    book.remark)))
    with io.BytesIO() as f:
        zipf = ZipFile(f, 'w')
        file_count = (lambda x: x / 3000 + (0 if x % 3000 == 0 else 1))(
            len(books))
        for i in range(file_count):
            lines = []
            try:
                for j in range(3000):
                    lines.append(book2csv(books[i*3000 + j]))
            except IndexError:
                pass
            zipf.writestr('{}.csv'.format(i + 1), '\n'.join(lines))
        f.seek(0)
        data = f.read()
    OperationLog.log(db.session, current_user)
    db.session.commit()
    return Response(
        (x for x in data),
        mimetype='application/zip',
        headers={
            'Content-Disposition': 'attachment;filename={}.csv'.format(
                peroid)})


@app.route('/paybook/public', methods=['GET'])
@admin_required
@OperationLog.log_template()
def paybook_public_report():
    money = func.sum(PayBook.money).label('money')
    query = db.session.query(
        Person.idcard.label('idcard'),
        Person.name.label('name'),
        Address.name.label('address_name'),
        Person.address_detail.label('address_detail'),
        money).join(
            PayBook, PayBook.person_id == Person.id).join(
                Address, Address.id == Person.address_id)
    mindate, maxdate = map(
        lambda x: request.args.get(x),
        ('mindate', 'maxdate'))
    if mindate:
        mindate = DateConverter.to_python(mindate)
        query = query.filter(PayBook.peroid >= mindate)
    if maxdate:
        maxdate = DateConverter.to_python(maxdate)
        query = query.filter(PayBook.peroid <= maxdate)
    books = query.group_by(
        PayBook.person_id).having(
            money > 0)

    def book2csv(book):
        return ','.join(
            map(
                lambda f: str(f),
                (
                    book.idcard,
                    book.name,
                    book.address_name,
                    book.address_detail,
                    book.money)))
    lines = map(book2csv, books)
    OperationLog.log(db.session, current_user)
    db.session.commit()
    return Response(
        (x for x in '\n'.join(lines)),
        mimetype="text/plain",
        headers={"Content-Disposition":
                 "attachment;filename=public_{}-{}.csv".format(
                     mindate, maxdate)})


@app.route('/paybook/check', methods=['GET', 'POST'])
@pay_admin_required
def paybook_check():
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        f = request.files.get('file')
        if f.read(len(codecs.BOM_UTF8)) != codecs.BOM_UTF8:
            f.seek(0)
        Reader = namedtuple(
            'Reader', 'securi_no,name,idcard,money,village_no,bankcard')
        bankcard_regex = re.compile(r'^((?:\d{19})|(?:\d{2}-\d{15})).*$')

        def validator(record):
            if not re.match(r'^\d{17}[\d|X]$', record.idcard):
                return False
            if not bankcard_regex.match(record.bankcard):
                return False
            return True
        unreg_bankcard, unreg_idcard = [], []
        for no, fields in enumerate(csv.reader(f, delimiter='|')):
            record = Reader._make(fields)
            if not validator(record):
                flash('synatx error in line:{}'.format(no + 1))
                abort(500)
            bankcard_no = bankcard_regex.match(record.bankcard).group(1)
            try:
                Bankcard.query.filter(Bankcard.no == bankcard_no).one()
            except NoResultFound:
                unreg_bankcard.append(bankcard_no)
            try:
                Person.query.filter(Person.idcard == record.idcard).one()
            except NoResultFound:
                unreg_idcard.append(record.idcard)

        def generator():
            yield 'bankcards:'
            for bankcard in unreg_bankcard:
                yield bankcard + '\n'
            yield 'idcards:'
            for idcard in unreg_idcard:
                yield idcard + '\n'
        return Response(
            generator(),
            mimetype="text/plain",
            headers={"Content-Disposition":
                     "attachment;filename=unreged.txt"})
    return render_template('upload.html', form=form)
