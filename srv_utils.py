import argparse
from datetime import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from run import db
from models import Person, Bankcard

Session = sessionmaker(bind=db.engine)


def _normal_from_line(line):
    idcard, remark = line.split(',')
    if remark != 'normal':
        return False
    session = Session()
    try:
        person = session.query(Person).filter(
            Person.idcard == idcard).one()
    except NoResultFound:
        return False
    if not person.can_normal:
        return False
    person.normal()
    session.commit()
    session.close()
    return True


def _retire_from_line(line):
    idcard, retire_day, remark = line.split(',')
    if remark != 'retire':
        return False
    retire_day = datetime.strptime(retire_day, '%Y-%m-%d').date()
    session = Session()
    try:
        person = session.query(Person).filter(
            Person.idcard == idcard).one()
    except NoResultFound:
        return False
    if not person.can_retire:
        return False
    person.retire(retire_day)
    session.commit()
    session.close()
    return True


def _dead_from_line(line):
    idcard, deadday, remark = line.split(',')
    if remark != 'dead':
        return False
    deadday = datetime.strptime(deadday, '%Y-%m-%d').date()
    session = Session()
    try:
        person = session.query(Person).filter(
            Person.idcard == idcard).one()
    except NoResultFound:
        return False
    if not person.can_dead_retire and not person.can_dead_unretire:
        return False
    person.dead(deadday)
    session.commit()
    session.close()
    return True


def _check_bankcard_from_line(line):
    no, name, remark = line.split(',')
    if remark != 'checkbankcard':
        return False
    session = Session()
    try:
        session.query(Bankcard).filter(
            Bankcard.no == no,
            Bankcard.name == name).one()
    except NoResultFound:
        return False
    return True


def _check_person_from_line(line):
    idcard, name, remark = line.split(',')
    if remark != 'checkperson':
        return False
    session = Session()
    try:
        session.query(Person).filter(
            Person.idcard == idcard,
            Person.name == name).one()
    except NoResultFound:
        return False
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Utils help update/insert date to db')
    parser.add_argument(
        '--operation', '-o',
        dest='operation', choices=(
            'normal', 'retire', 'dead', 'checkbankcard', 'checkperson'),
        help='the operation how to. options:\n' +
        'normal\n' +
        'retire\n' +
        'dead\n' +
        'checkbankcard\n' +
        'checkperson\n')
    parser.add_argument('--file', '-f',
                        dest='filename', help='the data file')

    args = parser.parse_args()
    try:
        with open(args.filename) as f:
            messages = ''
            messages_format = 'invalid line:{no}, content:{content}\n'
            fail_count = 0
            sucessed = False
            for no, line in enumerate(f):
                if args.operation == 'normal':
                    successed = _normal_from_line(line)
                if args.operation == 'retire':
                    successed = _retire_from_line(line)
                if args.operation == 'dead':
                    successed = _dead_from_line(line)
                if args.operation == 'checkbankcard':
                    successed = _check_bankcard_from_line(line)
                if args.operation == 'checkperson':
                    successed = _check_person_from_line(line)
                if not successed:
                    messages += messages_format.format(no, line)
                    fail_count += 1
                successed = True
            print(messages)
            print('total line count:{}. failed line count:{}.'.format(
                no + 1, fail_count))
    except IOError:
        print('file with name does not exists')
