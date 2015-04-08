from flask_wtf import Form
from wtforms_alchemy import model_form_factory
from wtforms import PasswordField
from wtforms.validators import Required
from models import db, User

BaseModelForm = model_form_factory(Form)


class ModelForm(BaseModelForm):
    @classmethod
    def get_session(cls):
        return db.session


class LoginForm(ModelForm):
    class Meta:
        model = User
        only = ['name', 'password']
        strip_string_fields = True
    password = PasswordField('password', validators=[Required()])


class UserForm(ModelForm):
    class Meta:
        model = User
