from flask_wtf import Form
from wtforms_alchemy import model_form_factory
from wtforms import PasswordField, TextField
from wtforms.validators import Required, EqualTo
from models import db, User, Address

BaseModelForm = model_form_factory(Form)


class ModelForm(BaseModelForm):
    @classmethod
    def get_session(cls):
        return db.session


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


class AddressForm(ModelForm):
    class Meta:
        model = Address
