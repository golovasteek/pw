#!/usr/bin/env python
import json
import gnupg
import getpass
import argparse
import pyperclip
import string
import random
import rumps

passwd = None
GNUPG_HOME = '~/.gnupg'
PW_FILE = './pw.gpg'


def getpw():
    global passwd
    if passwd is None:
        passwd = getpass.getpass()
    return passwd


def decode():
    gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
    p = getpw()
    decoded = gpg.decrypt(open(PW_FILE).read(), passphrase=p)
    if decoded.ok:
        return json.loads(decoded.data)
    else:
        print decoded.stderr
        raise RuntimeError("Can't decode file.")


def encode(data):
    gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
    p = getpw()
    encoded_data = gpg.encrypt(json.dumps(data), None, armor=False, symmetric=True, passphrase=p)
    open(PW_FILE, 'wb').write(str(encoded_data))


def print_keys():
    for key_id, user, pw in decode():
        if key_id:
            print key_id


def get_pw(requested_key):
    for key_id, user, pw in decode():
        if key_id == requested_key:
            print "Your user name is:", user
            pyperclip.copy(pw)
            print "Your password is copied to clipboard"


def generate_pw(pw_len=12):
    letter_classes = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "#!,.:;&%^()"
        ]
    all_letters = ''.join(letter_classes)
    passwd_letters = [
        random.choice(all_letters) for _ in range(pw_len - len(letter_classes))
        ] + [random.choice(cl) for cl in letter_classes]
    random.shuffle(passwd_letters)
    return ''.join(passwd_letters)


def set_pw(key_id, user, pw=None):
    if pw is None:
        pw = generate_pw()
    pw_data = decode()
    pw_data = filter(lambda x: x[0] != key_id, pw_data)
    pw_data.append([key_id, user, pw])
    encode(pw_data)
    get_pw(key_id)


def add_pw(key_id, user, pw=None):
    if key_id not in decode():
        set_pw(key_id, user, pw)


class PasswordHolderApp(rumps.App):
    def __init__(self):
        super(PasswordHolderApp, self).__init__('pw')
        self.update_menu()
        rumps.debug_mode(True)

    def update_menu(self):
        data = decode()
        items = [
            'Add',
            ['Stored', [rumps.MenuItem(key_id, callback=self.copy_key) for [key_id,_1,_2] in data if key_id]]
        ]
        self.menu.update(items)

    def copy_key(self, sender):
        for key_id, username, passwd in decode():
            if key_id == sender.title:
                pyperclip.copy(passwd)
                rumps.notification(
                    'Accest to {0}'.format(key_id),
                    'Your username is {0}'.format(username),
                    'Your password is copied into clipboard')

    @rumps.clicked('Add')
    def load_key(self, sender):
        response = rumps.Window("Registration data", "Enter key ID").run()
        if response.clicked:
            key_id = response.text
        else:
            return
        response = rumps.Window("Registration data", "Enter username").run()
        if response.clicked:
            username = response.text
        else:
            return
        add_pw(key_id, username)
        self.update_menu()



def run_osx_menu():
    global passwd
    response = rumps.Window('Please enter you master password', secure=True, dimensions=(240, 20)).run()
    if response.clicked:
        passwd = response.text
    else:
        raise RuntimeError('No password entered')
    PasswordHolderApp().run()


def main():
    parser = argparse.ArgumentParser(description="Manage encrypted key file")
    parser.add_argument('key_id', nargs='?', help="Key id to work with")
    parser.add_argument(
        '--print_keys', action='store_true',
        help="print names of known keys")
    parser.add_argument(
        '--get_pw', action='store_true',
        help="Print username and password on stdout")
    parser.add_argument('--add_pw', action='store_true')
    parser.add_argument('--password', default=None)
    parser.add_argument('--username')
    parser.add_argument(
            '--menu_mode', action='store_true',
            help='Run put application icon in menu-line and demonize')

    args = parser.parse_args()
    print args
    
    if args.print_keys:
        print "Printing key ids"
        print_keys()
    elif args.get_pw:
        print "Printing pw"
        get_pw(args.key_id)
    elif args.add_pw:
        add_pw(args.key_id, args.username, args.password)
    elif args.menu_mode:
        run_osx_menu()
        

if __name__ == "__main__":
    main()
