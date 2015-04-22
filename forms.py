from flask_wtf import Form
from wtforms_alchemy import model_form_factory
from wtforms import (
    PasswordField, TextField, SelectField, DateField)
from wtforms.validators import Required, EqualTo
from controller import db
from models import User, Role, Address


BaseModelForm = model_form_factory(Form)


class ModelForm(BaseModelForm):
    @classmethod
    def get_session(cls):
        return db.session


class PeroidForm(Form):
    start_date = DateField(unicode('start date'))
    end_date = DateField(unicode('end date'))


class LoginForm(Form):
    name = TextField('name', validators=[Required()])
    password = PasswordField('password', validators=[Required()])


class ChangePasswordForm(Form):
    oldpassword = PasswordField(u'old password', validators=[Required()])
    newpassword = PasswordField(u'new password', validators=[Required()])
    confirm = PasswordField(
        u'confirm password', validators=[EqualTo('newpassword')])

    def populate_obj(self, user, name=None):
        if name:
            user.name = name
        user.password = self.newpassword.data
        return user


class UserForm(ModelForm):
    class Meta:
        model = User
    password = PasswordField('password', validators=[Required()])


class _AdminRoleForm(Form):
    role = SelectField('role add/remove for user', coerce=int)

    def __init__(self, user, **kwargs):
        if user is None or not isinstance(user, User):
            raise ValueError("user can't be None and must a User instance")
        kwargs.update({'obj': user})
        super(_AdminRoleForm, self).__init__(**kwargs)


class AdminAddRoleForm(_AdminRoleForm):

    def __init__(self, user, **kwargs):
        super(AdminAddRoleForm, self).__init__(user, **kwargs)
        if user.roles:
            self.role.choices = map(
                lambda x: (x.id, x.name),
                Role.query.filter(
                    ~Role.id.in_(map(lambda x: x.id, user.roles))).all())
        else:
            self.role.choices = map(
                lambda x: (x.id, x.name), Role.query.all())

    def populate_obj(self, user):
        role = Role.query.get(self.role.data)
        user.roles.append(role)


class AdminRemoveRoleForm(_AdminRoleForm):
    def __init__(self, user, **kwargs):
        super(AdminRemoveRoleForm, self).__init__(user, **kwargs)
        if user.roles:
            self.role.choices = map(lambda x: (x.id, x.name), user.roles)
        else:
            self.role.choices = [(-1, '')]

    def populate_obj(self, user):
        if self.role.data > 0:
            role = Role.query.get(self.role.data)
            user.roles.remove(role)


class RoleForm(ModelForm):
    class Meta:
        model = Role


class AddressForm(ModelForm):
    parent_id = SelectField(unicode('parent id'), coerce=int)

    def __init__(self, **kwargs):
        super(AddressForm, self).__init__(**kwargs)
        address = kwargs.get('obj', None)
        if address and address.parent:
            query = Address.query.filter(Address.id != address.parent_id)
            if address.descendants:
                query = query.filter(~Address.id.in_(address.descendants))
        else:
            query = Address.query
        self.parent_id.choices = map(lambda x: (x.id, x.name), query.all())

    class Meta:
        model = Address
