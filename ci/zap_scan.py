"""Scan DVWA with ZAP, save reports, and apply a quality gate."""
import json
import os
import re
import sys
import time

import requests
from zapv2 import ZAPv2

TARGET = os.environ.get('TARGET', 'http://localhost').rstrip('/')
LOGIN = f'{TARGET}/login.php'
API_KEY = os.environ['ZAP_API_KEY']
LEVEL = os.environ.get('SECURITY_LEVEL', 'low')
MAX_HIGH = int(os.environ.get('MAX_HIGH', '0'))
SCAN_MINUTES = int(os.environ.get('SCAN_MINUTES', '15'))
# Pages that end the session, reset DVWA, or change the password
EXCLUDES = ['logout.php', 'setup.php', 'security.php', 'login.php', '/csrf/']


def wait(get_status, label, interval=5):
    while int(get_status()) < 100:
        print(f'[*] {label}: {get_status()}%')
        time.sleep(interval)
    print(f'[*] {label}: completed')


def dvwa_login():
    # DVWA login form requires an anti-CSRF token (user_token)
    s = requests.Session()
    page = s.get(LOGIN).text
    token = re.search(r"name='user_token' value='([^']+)'", page).group(1)
    r = s.post(LOGIN, data={'username': 'admin', 'password': 'password',
                            'Login': 'Login', 'user_token': token})
    if 'login.php' in r.url:
        sys.exit('[!] Login failed')
    return s.cookies.get('PHPSESSID')


def scan(zap):
    for page in EXCLUDES:
        zap.spider.exclude_from_scan(f'.*{page}.*')
        zap.ascan.exclude_from_scan(f'.*{page}.*')

    # Inject the logged-in session cookie into every ZAP request
    session_id = dvwa_login()
    zap.replacer.add_rule(description='dvwa-auth', enabled='true',
                          matchtype='REQ_HEADER', matchregex='false',
                          matchstring='Cookie',
                          replacement=f'PHPSESSID={session_id}; security={LEVEL}')
    print(f'[*] Logged in, security level = {LEVEL}')

    zap.core.access_url(TARGET, followredirects=True)
    sid = zap.spider.scan(TARGET)
    wait(lambda: zap.spider.status(sid), 'Spider')

    zap.ascan.set_option_max_scan_duration_in_mins(SCAN_MINUTES)
    aid = zap.ascan.scan(TARGET)
    wait(lambda: zap.ascan.status(aid), 'Active scan', interval=10)

    while int(zap.pscan.records_to_scan) > 0:
        time.sleep(2)


def report(zap):
    alerts = zap.core.alerts(baseurl=TARGET)
    with open('zap-report.html', 'w') as f:
        f.write(zap.core.htmlreport())
    with open('zap-alerts.json', 'w') as f:
        json.dump(alerts, f, indent=2)

    # One row per alert type (the same type appears on many URLs)
    types = {}
    for a in alerts:
        types.setdefault((a['risk'], a['alert']), []).append(a['url'])
    order = ['High', 'Medium', 'Low', 'Informational']
    counts = {r: sum(1 for k in types if k[0] == r) for r in order}

    lines = [f'## ZAP scan (DVWA security = {LEVEL})', '',
             '| Risk | Alert types |', '|---|---|']
    lines += [f'| {r} | {counts[r]} |' for r in order]
    lines += ['', '| Risk | Alert | URLs |', '|---|---|---|']
    for (risk, name), urls in sorted(types.items(), key=lambda kv: order.index(kv[0][0])):
        if risk in ('High', 'Medium'):
            lines.append(f'| {risk} | {name} | {len(urls)} |')
    summary = '\n'.join(lines)
    print(summary)

    # Shown on the workflow run page in GitHub Actions
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path, 'a') as f:
            f.write(summary + '\n')
    return counts['High']


def main():
    zap = ZAPv2(apikey=API_KEY, proxies={'http': 'http://127.0.0.1:8080',
                                         'https': 'http://127.0.0.1:8080'})
    print(f'[*] Connected to ZAP {zap.core.version}')
    scan(zap)
    high = report(zap)

    # Quality gate: a non-zero exit code marks the workflow run as failed
    if high > MAX_HIGH:
        sys.exit(f'[!] Quality gate failed: {high} High alert types (allowed: {MAX_HIGH})')
    print('[*] Quality gate passed')


if __name__ == '__main__':
    main()