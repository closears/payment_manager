import argparse
import codecs
from datetime import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from run import db, init
from models import Person, Bankcard, User, PayBook, PayBookItem

init()
Session = sessionmaker(bind=db.engine)


def _normal_from_line(line):
    idcard, remark = map(
        lambda s: s.decode('utf-8'),
        line.split(','))
    remark = remark.rstrip('\r').rstrip('\n')
    if remark != 'normal'.decode('utf-8'):
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
    idcard, retire_day, personal_wage, remark = map(
        lambda s: s.decode('utf-8'),
        line.split(','))
    remark = remark.rstrip('\r').rstrip('\n')
    if remark != 'retire'.decode('utf-8'):
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
    try:
        person.retire(retire_day)
        person.personal_wage = float(personal_wage)
    except Exception as e:
        print('age error:{}'.format(line))
        raise e
    session.commit()
    session.close()
    return True


def _dead_from_line(line):
    idcard, deadday, remark = map(
        lambda s: s.decode('utf-8'),
        line.split(','))
    remark = remark.rstrip('\r').rstrip('\n')
    if remark != 'dead'.decode('utf-8'):
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
    no, name, remark = map(
        lambda s: s.decode('utf-8'),
        line.split(','))
    remark = remark.rstrip('\r').rstrip('\n')
    if remark != 'checkbankcard'.decode('utf-8'):
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
    idcard, name, remark = map(
        lambda s: s.decode('utf-8'),
        line.split(','))
    remark = remark.rstrip('\r').rstrip('\n')
    if remark != 'checkperson'.decode('utf-8'):
        return False
    session = Session()
    try:
        session.query(Person).filter(
            Person.idcard == idcard,
            Person.name == name).one()
    except NoResultFound:
        return False
    return True


def _load_bankcard_from_line(line):
    bankcard_no, bankcard_name, idcard, remark = map(
        lambda s: s.decode('utf-8').rstrip('\n').rstrip('\r'),
        line.split(','))
    if remark != 'load_bankcard'.decode('utf-8'):
        return False
    session = Session()
    person = session.query(Person).filter(
        Person.idcard == idcard).first()
    if person is None:
        return False
    user = session.query(User).filter(
        User.name == 'admin').one()
    bankcard = session.query(Bankcard).filter(
        Bankcard.no == bankcard_no).first()
    if bankcard:
        bankcard.owner = person
    else:
        bankcard = Bankcard(
            no=bankcard_no, name=bankcard_name, create_by=user, owner=person)
    session.commit()
    session.close()
    return True


def _load_paybook_from_line(line):
    '''
    import file syntax:
    bankcard_no,money,success,peroid,remark
    6228410770613888888,75,1,2011-08-01,load_paybook
    '''
    session = Session()
    print(PayBook, PayBookItem)
    item_bank_should, item_bank_payed, item_bank_fail = map(
        lambda name: session.query(PayBookItem).filter(
            PayBookItem.name == name),
        ('bank_should_pay', 'bank_payed', 'bank_failed'))
    user = session.query(User).filter(User.name == 'admin').one()
    bankcard_no, money, successed, peroid, remark = map(
        lambda s: s.decode('utf-8'),
        line.split(','))
    remark = remark.rstrip('\r', '').rstrip('\n', '')
    if remark != 'load_paybook'.decode('utf-8'):
        return False
    bankcard = session.query(Bankcard).filter(
        Bankcard.no == bankcard_no).first()
    if bankcard is None or not bankcard.binded:
        return False
    if successed == '1':
        to_item = item_bank_payed
    else:
        to_item = item_bank_fail
    session.add(PayBook.create_tuple(
        bankcard.owner_id, item_bank_should.id, to_item.id,
        bankcard.id, bankcard.id, float(money),
        datetime.strptime(peroid, '%Y-%m-%d'), user.id))
    session.commit()
    session.close()
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Utils help update/insert data to db')
    parser.add_argument(
        '--operation', '-o',
        dest='operation', choices=(
            'normal', 'retire', 'dead', 'checkbankcard', 'checkperson',
            'load_bankcard'),
        help='the operation how to. options:\n' +
        'normal\n' +
        'retire\n' +
        'dead\n' +
        'checkbankcard\n' +
        'checkperson\n' +
        'load_bankcard\n' +
        'load_paybook\n')
    parser.add_argument('--file', '-f',
                        dest='filename', help='the data file')

    args = parser.parse_args()
    try:
        with open(args.filename) as f:
            if f.read(len(codecs.BOM_UTF8)) != codecs.BOM_UTF8:
                f.seek(0)
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
                if args.operation == 'load_bankcard':
                    successed = _load_bankcard_from_line(line)
                if args.operation == 'load_paybook':
                    successed = _load_paybook_from_line(line)
                if not successed:
                    messages += messages_format.format(no=no, content=line)
                    fail_count += 1
                successed = True
            print(messages)
            print('total line count:{}. failed line count:{}.'.format(
                no + 1, fail_count))
    except IOError:
        print('file with name:{} does not exists'.format(
            args.filename))
