from flask_wtf import Form
from wtforms_alchemy import model_form_factory
from wtforms import PasswordField, TextField
from wtforms.validators import Required
from models import db, User, Address

BaseModelForm = model_form_factory(Form)


class ModelForm(BaseModelForm):
    @classmethod
    def get_session(cls):
        return db.session


class LoginForm(Form):
    name = TextField('name', validators=[Required()])
    password = PasswordField('password', validators=[Required()])


class UserForm(ModelForm):
    class Meta:
        model = User


class AddressForm(ModelForm):
    class Meta:
        model = Address
