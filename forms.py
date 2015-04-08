from wtforms import TextField, PasswordField, Required
from wtforms_alchemy import ModelForm
from models import User


class LoinForm(ModelForm):
    class Meta:
        model = User
        only = ['name', 'password']
    password = PasswordField('password', validators=[Required()])


class UserForm(ModelForm):
    class Meta:
        model = User


def class_info():
    print(dir(Form))
    print(TextField)
