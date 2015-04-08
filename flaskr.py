from flask import Flask
from flask import render_template, request


app = Flask(__name__)
# app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)


@app.route('/')
def index():
    return render_template('index.html', name='World')


@app.route('/test', methods=['GET', 'POST'])
def test():
    if request.method == 'GET':
        return '''
<!DOCTYPE html>
<html>
\t<head>
\t\t<title>test</title>
\t</head>
\t<body>
\t\t<form method='POST'>
\t\t\t<textarea type='textarea' name='textarea' rows=3></textarea>
\t\t\t<input type='submit' value='submit'>
\t\t</form>
\t</body>
</html>'''
    if request.method == 'POST':
        for line in request.form['textarea'].splitlines():
            print(line)
    return 'success'
