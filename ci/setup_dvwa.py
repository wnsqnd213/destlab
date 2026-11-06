import os
import re
import sys
import time
import requests

TARGET = os.environ.get("TARGET", "http://localhost").rstrip("/")
SETUP = f'{TARGET}/setup.php'


def get_token(html):
    return re.search(r"name='user_token' value='([^']+)'", html).group(1)


def main():
    s = requests.Session()

    for _ in range(60):
        try:
            if s.get(SETUP, timeout=5).status_code == 200:
                break
        except requests.RequestException:
            pass
        print('[*] Waiting for DVWA...')
        time.sleep(5)
    else:
        sys.exit('[!] DVWA did not start')

    token = get_token(s.get(SETUP).text)
    r = s.post(SETUP, data={
        'create_db': 'Create / Reset Database',
        'user_token': token
    })
    if 'Setup successful' not in r.text:
        sys.exit('[!] Database setup failed')

    print('[*] DVWA database created')


if __name__ == '__main__':
    main()