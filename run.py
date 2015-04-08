# coding=utf-8
from controller import app

if __name__ == '__main__':
    app.config.from_pyfile('config.cfg', silent=True)
    app.run()
