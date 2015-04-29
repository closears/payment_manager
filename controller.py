from datetime import datetime
from sqlalchemy.orm.exc import NoResultFound
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
from models import app, db, User, Role, Address, Person, OperationLog
from flask_wtf.csrf import CsrfProtect
from forms import (
    Form, LoginForm, ChangePasswordForm, UserForm, AdminAddRoleForm,
    AdminRemoveRoleForm, RoleForm, PeroidForm, AddressForm, PersonForm)


class RegexConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex = args[0]

app.url_map.converters['regex'] = RegexConverter

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

CsrfProtect(app)
Principal(app)
admin_required = Permission(RoleNeed('admin')).require(403)


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
    return redirect('/login')


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
    form = Form()
    if request.method == 'POST' and form.validate_on_submit():
        OperationLog.log(db.session, current_user, user=user)
        db.session.delete(user)
        db.session.commit()
        return 'success'
    return render_template(
        'admin_remove_user.html', form=form, user=user)


@app.route('/admin/user/<int:pk>/inactivate', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }}')
def admin_user_inactivate(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash(unicode('no user find with pk:{}').format(pk))
        abort(404)
    if request.method == 'GET':
        return render_template(
            'admin_user_inactivate.html', form=UserForm(obj=user))
    OperationLog.log(db.session, current_user, user=user)
    user.active = False
    db.session.commit()
    return 'success'


@app.route('/admin/user/<int:pk>/activate', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }}')
def admin_user_activate(pk):
    try:
        user = User.query.filter(User.id == pk).one()
    except NoResultFound:
        flash(unicode('no user find with pk:{}').format(pk))
        abort(404)
    if request.method == 'GET':
        return render_template(
            'admin_user_activate.html', form=UserForm(obj=user))
    user.active = True
    OperationLog.log(db.session, current_user, user=user)
    db.session.commit()
    return 'success'


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
    form = Form()
    if request.method == 'POST' and form.validate_on_submit():
        for user in role.users:
            user.remove(role)
            db.session.commit()
        db.session.delete(role)
        db.session.commit()
        return 'success'
    return render_template('admin_role_remove.html', role=role, form=form)


date_regex = r"(:?\d{4}-\d{2}-\d{2})"


@app.route(
    '/admin/log/search?operator-id=<int:operator_id>' +
    '&start_date=<regex("{}"):start_date>'.format(date_regex) +
    '&end_date=<regex("{}"):end_date>'.format(date_regex) +
    '&page=<int:page>&per_page=<int:per_page>',
    methods=['GET']
)
@admin_required
def admin_log_search(operator_id, start_date, end_date, page, per_page):
    pagination = OperationLog.query.filter(
        OperationLog.operator_id == operator_id).filter(
            OperationLog.time >= datetime.strptime(start_date, '%Y-%m-%d')
            ).filter(
                OperationLog.time <= datetime.strptime(end_date, '%Y-%m-%d')
            ).paginate(page, per_page)
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
            start_date = datetime.fromordinal(form.start_date.data.toordinal())
            query = query.filter(OperationLog.time >= start_date)
        if form.end_date.data:
            end_date = datetime.fromordinal(form.end_date.data.toordinal())
            query = query.filter(OperationLog.time <= end_date)
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
    form = Form()
    if request.method == 'POST' and form.validate_on_submit():
        for descendant in address.descendants:
            db.session.delete(descendant)
            OperationLog.log(db.session, current_user, address=descendant)
        db.session.delete(address)
        OperationLog.log(db.session, current_user, address=address)
        db.session.commit()
        return 'success'
    return render_template('address_delete.html', address=address, form=form)


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
@OperationLog.log_template()
def address_search(name, page, per_page):
    query = Address.query.filter(
        Address.id.in_([a.id for a in current_user.address.descendants]),
        Address.name.like(unicode('{}%').format(name)))
    return render_template(
        'address_search.html', pagination=query.paginate(page, per_page))


@app.route('/person/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ person.idcard }}')
def person_add():
    form = PersonForm(current_user, formdata=request.form)
    if request.method == 'POST' and form.validate_on_submit():
        person = Person()
        form.populate_obj(person)
        db.session.add(person)
        db.session.commit()
        return 'success'
    return render_template('person_add.html', form=form)
