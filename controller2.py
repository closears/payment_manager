from sqlalchemy import NoResultFound
import flask
from flask import (
    render_template, session, request, flash, abort, redirect, current_app)
from flask_login import LoginManager, current_user, login_required, login_user
from flask_principal import (
    Principal, Permission, Need, UserNeed, RoleNeed, identity_loaded,
    identity_changed, Identity)
from models import app, User, Address, Person, OperationLog

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    if hasattr(current_user, 'address'):
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
    OperationLog.log()
    return redirect(request.args.get('next') or '/')

print(app)
