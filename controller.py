import csv
import codecs
import re
from collections import namedtuple
from datetime import datetime, date
from sqlalchemy import exists, and_
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from werkzeug.routing import BaseConverter
from werkzeug.datastructures import MultiDict
import flask
from flask import (
    render_template, session, request, flash, abort, redirect, current_app,
    url_for)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user)
from flask_principal import (
    Principal, Permission, Need, UserNeed, RoleNeed, identity_loaded,
    identity_changed, Identity)
from models import (
    app, db, User, Role, Address, Person, OperationLog, PersonStatusError,
    PersonAgeError, Standard, Bankcard, Note, PayBookItem, PayBook)
from flask_wtf.csrf import CsrfProtect
from forms import (
    Form, LoginForm, ChangePasswordForm, UserForm, AdminAddRoleForm,
    AdminRemoveRoleForm, RoleForm, PeroidForm, AddressForm, PersonForm,
    DateForm, StandardForm, StandardBindForm, BankcardForm, BankcardBindForm,
    NoteForm, PayItemForm)


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

    def to_python(self, value):
        return value and datetime.strptime(value, '%Y-%m-%d').date()

    def to_url(self, value):
        return value.strftime('%Y-%m-%d') if isinstance(
            value, (datetime, date)) else value


class DateTimeConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex = r'\d{4}-\d{2}-\d{2}'

    def to_python(self, value):
        return value and datetime.strptime(value, '%Y-%m-%d')

    def to_url(self, value):
        return value.strftime('%Y-%m-%d') if isinstance(
            value, (datetime, date)) else value


class NoneConverter(BaseConverter):

    def to_python(self, value):
        return None if value == 'None' else value

    def to_url(self, value):
        return str(value)


class BooleanConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex == 'yes|no'

    def to_python(self, value):
        return value == 'yes'

    def to_url(self, value):
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
        Person.query = Person.query.filter(Person.address_id.in_(ids))
        for id in ids:
            identity.provides.add(AddressAccessPermission(id))


@app.errorhandler(404)
def page_not_found(error):
    session.get('back_url', None) or session.update(back_url='/')
    return render_template('404.html'), 404


@app.errorhandler(500)
def page_error(error):
    session.get('back_url', None) or session.update(back_url='/')
    return render_template('500.html'), 500


@app.errorhandler(403)
def page_forbiden(error):
    session.get('back_url', None) or session.update(back_url='/')
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
        redirect_url = '/login?next={}'.format(request.args.get('next') or '/')
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
        return redirect(request.args.get('next') or '/')
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
def user_changpassword():
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


@app.route('/admin/user/<int:pk>/detail', methods=['GET'])
@admin_required
def admin_user_detail(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash("The user with pk{} was't find".format(pk))
        abort(404)
    return render_template('admin_user_detail.html', user=user)


@app.route(
    '/admin/user/search?name=<regex(r"(:?[a-zA-Z][a-zA-Z_0-9]*)?"):name>' +
    'page=<int:page>&per_page=<int:per_page>',
    methods=['GET']
)
@admin_required
def admin_user_search(name, page, per_page):
    pagination = User.query.filter(
        User.name.like('{}%'.format(name))).paginate(page, per_page)
    return render_template('admin_user_search.html', pagination=pagination)


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
            user.remove(role)
            db.session.commit()
        db.session.delete(role)
        db.session.commit()
        return 'success'
    return render_template(
        'confirm.html', form=form, title='role remove', message=unicode(
            'confirm delete the role:{}').format(role.name))


@app.route(
    '/admin/log/search?operator-id=<int:operator_id>' +
    '&start_date=<datetime:start_date>&end_date=<datetime:end_date>' +
    '&page=<int:page>&per_page=<int:per_page>',
    methods=['GET']
)
@admin_required
def admin_log_search(operator_id, start_date, end_date, page, per_page):
    pagination = OperationLog.query.filter(
        OperationLog.operator_id == operator_id).filter(
            OperationLog.time >= start_date).filter(
                OperationLog.time <= end_date).paginate(page, per_page)
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
        query = OperationLog.query.filter(OperationLog.id == operator_id)
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
        if address.descendant_of(current_user.address):
            identity_changed.send(
                current_app._get_current_object(),
                identity=Identity(current_user.id))
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
    '/address/search?name=<name>&page=<int:page>&per_page=<int:per_page>',
    methods=['GET'])
@login_required
def address_search(name, page, per_page):
    query = Address.query.filter(
        Address.id.in_([a.id for a in current_user.address.descendants]),
        Address.name.like(unicode('{}%').format(name)))
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


@app.route('/person/<int:pk>/delete', methods=['GET', 'POST'])
@admin_required
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
@OperationLog.log_template('{{ person.id }},')
def person_regire_reg(pk):
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
@OperationLog.log_template('{{ person.id }},')
def person_batch_normal():
    form = PeroidForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        persons = Person.query.filter(
            Person.can_normal.is_(True)).filter(
                Person.birthday >= form.start_date.data).filter(
                    Person.birthday <= form.end_date.data).all()
        for person in persons:
            person.normal()
            OperationLog.log(db.session, current_user, person=person)
        db.session.commit()
        return 'succes'
    return render_template('person_batch_normal.html', form=form)


@app.route('/person/<int:pk>/dead_reg', methods=['GET', 'POST'])
@admin_required
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


@app.route('/person/<int:pk>/address_change', methods=['GET', 'POST'])
@admin_required
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


@app.route('/person/search?idcardlike=<none:idcard>&namelike=<none:name>' +
           'addresslike=<none:address>&page=<int:page>&perpage=<int:per_page>',
           methods=['GET'])
@login_required
def person_search(idcard, name, address, page, per_page):
    query = Person.query
    if idcard:
        query = query.filter(Person.idcard.like('{}%'.format(idcard)))
    if name:
        query = query.filter(Person.name.like('{}%'.format(name)))
    if address:
        stmt = exists().where(and_(
            Person.address_id == Address.id,
            Address.name.like('{}%'.format(address))))
        query = query.filter(stmt)
    return render_template('person_search.html',
                           pagination=query.paginate(page, per_page))


@app.route('/person/<int:pk>/standardbind', methods=['GET', 'POST'])
@admin_required
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


@app.route('/person/<int:pk>/logsearch?' +
           'startdate=<date:start_date>&enddate=<date:end_date>' +
           '&operatorid=<int:operator_id>' +
           '&page=<int:page>&perpage=<int:per_page>', methods=['GET'])
@login_required
def person_log_search(pk, start_date, end_date, operator_id, page, per_page):
    query = OperationLog.query.filter(
        OperationLog.method.in_([m.__name__ for m in (
            person_abort_reg,
            person_add,
            person_batch_normal,
            person_dead_reg,
            person_delete,
            person_normal_reg,
            person_regire_reg,
            person_resume_reg,
            person_suspend_reg,
            person_update)])).filter(
                OperationLog.remark.like('{},%'.format(pk))).filter(
                    OperationLog.time >= start_date).filter(
                        OperationLog.time <= end_date).filter(
                            OperationLog.operator_id == operator_id)
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
@OperationLog.log_template('{{ bankcard.id }},{{ bankcard.owner.idcard }}' +
                           '{% if person %}-old owner{% endif %}')
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
        bankcard.owner = person
        OperationLog.log(db.session, current_user, bankcard=bankcard)
        db.session.commit()
        return 'success'


@app.route('/bankcard/<int:pk>/update', methods=['GET', 'POST'])
@admin_required
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


@app.route('/bankcard/search?nolike=<no>&namelike=<name>' +
           '&idcardlike=<none:idcard>&page=<int:page>&per_page=<int:per_page>',
           methods=['GET'])
@login_required
def bankcard_search(no, name, idcard, page, per_page):
    stmt = exists().where(and_(
                          Bankcard.owner_id == Person.id,
                          Person.address_id == Address.id,
                          Address.id == current_user.address.id))
    query = Bankcard.query.filter(stmt)
    if no:
        query = query.filter(Bankcard.no.like('{}%'.format(no)))
    if name:
        query = query.filter(Bankcard.name.like('{}%'.format(name)))
    if idcard:
        stmt = exists().where(and_(
                              Bankcard.owner_id == Person.id,
                              Person.idcard.like('{}%'.format(idcard))))
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


@app.route('/note/list/finished/<boolean:finished>?' +
           'page=<int:page>&per_page=<int:per_page>',
           methods=['GET'])
@login_required
def note_search(finished, page, per_page):
    query = Note.query.filter(Note.user_id == current_user.id).filter(
        Note.effective.is_(True)).filter(
            Note.finished == finished)
    return render_template('note_search.html', pagination=query.paginate(
        page, per_page))


@app.route('/note/touser/<int:user_id>', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user_id }}')
def note_to_urer(user_id):
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


@app.route('/paybook/upload/<date:peroid>', methods=['GET', 'POST'])
@pay_admin_required
def paybook_upload(peroid):
    form = Form(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        file = request.files['file']
        Reader = namedtuple('Reader',
                            'securi_no,name,idcard,money,village_no,bankcard')
        line_no = 1

        def validate(record):
            if not re.match(r'^(?:(?:\d{19})|(?:\d{2}-\d{15}))[\w\W]*$',
                            record.bankcard):
                return False
            if not re.match(r'^\d{17}[\d|X]$', record.idcard):
                return False
            if not re.match(r'^\d+(?:\.\d{2})?$', record.money):
                return False
            return True
        for line in file:
            line = line.replace(codecs.BOM_UTF8, '').replace('|', ',').rstrip(
                ',')
            fields = map(lambda x: codecs.decode(x, 'utf-8'),
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
                person, item1, item2, bankcard, bankcard, float(record.money),
                peroid, current_user))
            line_no += 1
        db.session.commit()
        return 'success'
    return render_template('upload.html', form=form)
# TODO add pay book search, pay book amend, pay book forward
# pay book export, pay book batch forward, remove payitem default item to
# controller


'''Response(generator,
                       mimetype="text/plain",
                       headers={"Content-Disposition":
                                    "attachment;filename=test.txt"})'''
