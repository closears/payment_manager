from sqlalchemy.orm.exc import NoResultFound
from werkzeug.routing import BaseConverter
import flask
from flask import (
    render_template, session, request, flash, abort, redirect, current_app)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user)
from flask_principal import (
    Principal, Permission, Need, UserNeed, RoleNeed, identity_loaded,
    identity_changed, Identity)
from models import app, db, User, Address, Person, OperationLog
from flask_wtf.csrf import CsrfProtect
from forms import LoginForm, ChangePasswordForm, UserForm


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
admin_required = Permission(RoleNeed('admin')).require()


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
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))
    if hasattr(current_user, 'address') and current_user.address:
        ids = [address.id for address in current_user.address.descendants()]
        Address.query = Address.query.filter(Address.id.in_(ids))
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
        if request.form.get('address_id', None):
            if not AddressAccessPermission(
                    int(request.form['address_id'])).can():
                flash(
                    unicode('You can not access address with id{}').format(
                        request.form['address_id']))
                abort(403)
        method = request.form.get('_method', '').upper()
        if method:
            request.environ['REQUEST_METHOD'] = method
            ctx = flask._request_ctx_stack.top
            ctx.url_adapter.default_method = method
            assert request.method == method


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
        OperationLog.log(user=current_user)
        return redirect(request.args.get('next') or '/')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET'])
@login_required
@OperationLog.log_template()
def logout():
    OperationLog.log(user=current_user)
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
    if request.method == 'GET':
        return render_template(
            'admin_remove_user.html', form=UserForm(obj=user))
    db.session.delete(user)
    db.session.commit()
    return 'success'


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
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
    return render_template('admin_user_changepassword.html', form=form)


@app.route(
    '/admin/user/<int:pk>/addrole', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }},{{ newroles }}')
def admin_user_add_role(pk):
    pass


@app.route(
    '/admin/user/<int:pk>/removerole', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ user.id }},{{ removed_roles }}')
def admin_user_remove_role(pk):
    pass


@app.route('/admin/user/<int:pk>/detail', methods=['GET'])
@admin_required
def admin_user_detail(pk):
    pass


@app.route(
    '/admin/user/search?name=<regex(r"(:?[a-zA-Z][a-zA-Z_0-9]*)?"):name>',
    methods=['GET']
)
@admin_required
def admin_user_search():
    pass


@app.route('/admin/role/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ role.id }}')
def admin_role_add():
    pass


@app.route('/admin/role/<int:pk>/romve', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template('{{ role.name }}')
def admin_role_romove(pk):
    pass


date_regex = r"(:?\d{4}-\d{2}-\d{2})"


@app.route(
    '/admin/log/search?user-id=<int:user_id>' +
    '&start_date=<regex("{}"):start_date>'.format(date_regex) +
    '&end_date=<regex("{}"):end_date>'.format(date_regex),
    methods=['GET']
)
@admin_required
def admin_log_search(user_id, start_date, end_date):
    pass


@app.route('/address/add', methods=['GET', 'POST'])
@admin_required
@OperationLog.log_template()
def address_add():
    pass
