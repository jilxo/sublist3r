#!/usr/bin/env python
# coding: utf-8
# Sublist3r v1.0
# By Ahmed Aboul-Ela - twitter.com/aboul3la

# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Python 2.x and 3.x compatiablity
if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
        #Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed, no coloring will be used [Check the readme]")
        G = Y = B = R = W = G = Y = B = R = W = ''


else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''


def banner():
    print(r"""%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s

                # Coded By Ahmed Aboul-Ela - @aboul3la
    """ % (R, W, Y))


def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()


def write_file(filename, subdomains):
    # saving subdomains results to output file
    print("%s[-] Saving results to file: %s%s%s%s" % (Y, W, R, filename, W))
    with open(str(filename), 'wt') as f:
        for subdomain in subdomains:
            f.write(subdomain + os.linesep)


def subdomain_sorting_key(hostname):
    """Sorting key for subdomains

    This sorting key orders subdomains from the top-level domain at the right
    reading left, then moving '^' and 'www' to the top of their group. For
    example, the following list is sorted correctly:

    [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]

    """
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0


class enumratorBase(object):
    """Base class for all enumerator implementations.
    
    This class implements core functionality for making HTTP requests while avoiding
    detection and blocking:
    
    - Modern browser headers and User-Agent rotation
    - Exponential backoff for rate limiting
    - Automatic retry with increased delays when blocked
    - Request spacing to stay under rate limits
    
    The anti-blocking measures include:
    1. Rotating between modern browser User-Agents
    2. Using realistic headers including security-related ones
    3. Implementing exponential backoff when rate limited
    4. Adding random delays between requests
    5. Automatic detection of blocking/rate limiting
    """
    
    # Lista moderna de User-Agents para rotar
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/118.0.2088.76'
    ]

    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self._ua_index = 0
        self._last_ua_rotation = 0
        self._last_request_time = 0  # Inicializar el tiempo del último request
        self._retry_count = 0  # Inicializar contador de reintentos
        self._ua_rotation_interval = 30  # Rotar UA cada 30 segundos
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive'
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        """ subclass can override this if they want a fancy banner :)"""
        self.print_(G + "[-] Searching now in %s.." % (self.engine_name) + W)
        return

    def rotate_user_agent(self):
        """Rotate User-Agent header periodically"""
        now = time.time()
        if now - self._last_ua_rotation >= self._ua_rotation_interval:
            self._ua_index = (self._ua_index + 1) % len(self.USER_AGENTS)
            self._last_ua_rotation = now
            self.headers['User-Agent'] = self.USER_AGENTS[self._ua_index]

    def send_req(self, query, page_no=1):
        """Send HTTP request with automatic User-Agent rotation and rate limiting"""
        url = self.base_url.format(query=query, page_no=page_no)
        
        # Rotate UA before request
        self.rotate_user_agent()
        
        # Apply rate limiting
        self.should_sleep()
        
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            
            # Check for rate limiting
            if self.handle_rate_limit(self.get_response(resp)):
                # Retry once with increased delay if rate limited
                self.should_sleep()
                resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            if self.verbose:
                self.print_(R + "[!] Request failed: %s" % str(e) + W)
            resp = None
            
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    # override
    def extract_domains(self, resp):
        """ chlid class should override this function """
        return

    # override
    def check_response_errors(self, resp):
        """ chlid class should override this function
        The function should return True if there are no errors and False otherwise
        """
        return True

    def should_sleep(self):
        """Some enumrators require sleeping to avoid bot detections like Google enumerator"""
        # Default implementation with exponential backoff
        if not hasattr(self, '_retry_count'):
            self._retry_count = 0
        if not hasattr(self, '_last_request_time'):
            self._last_request_time = 0

        now = time.time()
        min_delay = 2.0  # Base delay between requests
        
        # Calculate delay with exponential backoff
        if self._retry_count > 0:
            delay = min(min_delay * (2 ** self._retry_count), 30)  # Max 30 seconds
        else:
            delay = min_delay

        # Ensure minimum time between requests
        elapsed = now - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        
        self._last_request_time = time.time()
        return

    def handle_rate_limit(self, resp):
        """Handle rate limiting and update retry strategy"""
        rate_limit_phrases = [
            'rate limit exceeded',
            'too many requests',
            'unusual traffic',
            'temporary block',
            'please wait',
            'access denied',
            'blocked'
        ]
        
        # Check response for rate limit indicators
        is_limited = False
        if resp and isinstance(resp, str):
            resp_lower = resp.lower()
            is_limited = any(phrase in resp_lower for phrase in rate_limit_phrases)
        
        if is_limited:
            if not hasattr(self, '_retry_count'):
                self._retry_count = 0
            self._retry_count += 1
            self.should_sleep()  # Apply backoff
            return True
        
        # Reset retry count on success
        self._retry_count = 0
        return False

    def generate_query(self):
        """ child class should override this function """
        return

    def get_page(self, num):
        """ chlid class that user different pagnation counter should override this function """
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain)  # finding the number of subdomains found so far

            # if they we reached the maximum number of subdomains in search query
            # then we should go over the pages
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):  # maximum pages for Google to avoid getting blocked
                return self.subdomains
            resp = self.send_req(query, page_no)

            # check if there is any error occured
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

            # if the previous page hyperlinks was the similar to the current one, then maybe we have reached the last page
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

        # make another retry maybe it isn't the last page
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains


class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)


class GoogleEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile(r'<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if isinstance(resp, str) and 'Our systems have detected unusual traffic' in resp:
            self.print_(R + "[!] Error: Google probably now is blocking our requests" + W)
            self.print_(R + "[~] Finished now the Google Enumeration ..." + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query


class YahooEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx2 = re.compile('<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r"<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query


class AskEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)

        return query


class BingEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent)
        self.q = q
        self.verbose = verbose
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2

            for link in links_list:
                link = re.sub(r'<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query


class BaiduEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        links = list()
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query


class NetcraftEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.engine_name = "Netcraft"
        super(NetcraftEnum, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def req(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            self.print_(e)
            resp = None
        return resp

    def should_sleep(self):
        time.sleep(random.randint(1, 2))
        return

    def get_next(self, resp):
        link_regx = re.compile('<a.*?href="(.*?)">Next Page')
        link = link_regx.findall(resp)
        url = 'http://searchdns.netcraft.com' + link[0]
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # hashlib.sha1 requires utf-8 encoded str
        cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain=self.domain)
        while True:
            resp = self.get_response(self.req(url, cookies))
            self.extract_domains(resp)
            if 'Next Page' not in resp:
                return self.subdomains
                break
            url = self.get_next(resp)
            self.should_sleep()

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<a class="results-table__host" href="(.*?)"')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list


class DNSdumpster(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.api_base = 'https://api.dnsdumpster.com/domain'
        self.live_subdomains = []
        self.engine_name = "DNSdumpster"
        self.q = q
        self.lock = None
        
        # Initialize base class first so self.verbose is set
        super(DNSdumpster, self).__init__(self.api_base, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        
        # Get API key after base class initialization
        self.api_key = self.get_api_key()
        
        if not self.api_key:
            if self.verbose:
                self.print_(R + "[!] DNSdumpster requires an API key to work" + W)
                self.print_(Y + "    Get your key from https://dnsdumpster.com" + W)
                self.print_(Y + "    Then set DNSDUMPSTER_KEY environment variable" + W)
                self.print_(Y + "    Or save it to ~/.dnsdumpster_api_key" + W)
        elif self.verbose:
            self.print_(G + "[-] DNSdumpster: API key configured correctly" + W)
            
        # Set custom headers for DNSdumpster API
        self.headers = {
            'X-API-Key': self.api_key,
            'Accept': 'application/json',
            'User-Agent': 'Sublist3r/1.0'
        }
        
        return

    def get_api_key(self):
        """
        Obtain and validate DNSdumpster API key.
        
        Priority:
        1. Environment variable DNSDUMPSTER_API_KEY or DNSDUMPSTER_KEY
        2. File in user's home directory named .dnsdumpster_api_key
        
        Returns:
            str: Valid API key if found
            None: If no valid key found
        
        Note: API keys must be 64 character hexadecimal strings
        """
        def is_valid_key(k):
            """Validate key format: 64 hex chars"""
            if not k:
                return False
            k = k.strip()
            # Check for exactly 64 hexadecimal characters
            if not re.match(r'^[a-f0-9]{64}$', k.lower()):
                if self.verbose:
                    self.print_(R + "[!] Invalid API key format - must be exactly 64 hexadecimal characters" + W)
                return False
            return True
        
        # Try environment variables first
        for env_var in ['DNSDUMPSTER_API_KEY', 'DNSDUMPSTER_KEY']:
            key = os.environ.get(env_var, '').strip()
            if key:
                if is_valid_key(key):
                    if self.verbose:
                        self.print_(G + f"[-] Using DNSdumpster API key from {env_var}" + W)
                    return key
                else:
                    if self.verbose:
                        self.print_(R + f"[!] Invalid API key format in {env_var} - must be 64 hex chars" + W)

        # Try config file
        try:
            home = os.path.expanduser('~')
            path = os.path.join(home, '.dnsdumpster_api_key')
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    key = f.read().strip()
                    if self.verbose:
                        self.print_(Y + f"[-] Found API key in config file: {key[:8]}..." + W)
                    if is_valid_key(key):
                        self.print_(G + "[-] Using DNSdumpster API key from config file" + W)
                        return key
                    else:
                        if self.verbose:
                            self.print_(R + "[!] Invalid API key in config file:" + W)
                            self.print_(R + f"    Found key: {key}" + W)
                            self.print_(R + "    Key must be exactly 64 hexadecimal characters" + W)
        except Exception as e:
            if self.verbose:
                self.print_(R + f"[!] Error reading API key file: {str(e)}" + W)

        if self.verbose:
            self.print_(Y + "[!] No valid DNSdumpster API key found. To use the API:" + W)
            self.print_(Y + "    1. Get your key from https://dnsdumpster.com" + W)
            self.print_(Y + "    2. Set DNSDUMPSTER_KEY environment variable" + W)
            self.print_(Y + "    3. Or save to ~/.dnsdumpster_api_key" + W)
        
        return None

    def check_host(self, host):
        """Verify if a subdomain resolves to an IP address"""
        is_valid = False
        Resolver = dns.resolver.Resolver()
        Resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.lock.acquire()
        try:
            ip = Resolver.resolve(host, 'A')[0].to_text()
            if ip:
                if self.verbose:
                    self.print_("%s%s: %s%s" % (R, self.engine_name, W, host))
                is_valid = True
                self.live_subdomains.append(host)
        except:
            pass
        self.lock.release()
        return is_valid

    def enumerate(self):
        """
        Use the DNSdumpster API to enumerate subdomains.
        
        This method requires a valid API key and follows the rate limits:
        - 1 request per 2 seconds
        - Supports pagination for results (Plus accounts only)
        - Returns validated subdomains
        
        Returns:
            list: List of validated subdomains that were found
        """
        if not self.api_key:
            self.print_(R + "[!] DNSdumpster requires an API key to work" + W)
            return self.live_subdomains

        self.lock = threading.BoundedSemaphore(value=70)
        
        try:
            # Construct the API URL properly
            url = f"{self.api_base}/{self.domain}"
            
            # Apply rate limiting
            time.sleep(2)  # Respect 1 req/2s limit
            
            if self.verbose:
                self.print_(Y + f"[-] Querying DNSdumpster API: {url}" + W)
            
            # Make the API request
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            
            # Handle HTTP errors
            if resp.status_code == 401:
                self.print_(R + "[!] DNSdumpster API Error: Invalid credentials" + W)
                self.print_(Y + "    Please verify your API key at https://dnsdumpster.com" + W)
                return self.live_subdomains
            elif resp.status_code == 429:
                self.print_(R + "[!] DNSdumpster API rate limit exceeded (1 req/2s)" + W)
                return self.live_subdomains
            elif resp.status_code != 200:
                self.print_(R + f"[!] DNSdumpster API Error: HTTP {resp.status_code}" + W)
                return self.live_subdomains

            # Parse the JSON response
            try:
                data = resp.json()
            except json.JSONDecodeError:
                self.print_(R + "[!] Failed to parse DNSdumpster API response" + W)
                return self.live_subdomains

            if isinstance(data, dict) and 'error' in data:
                self.print_(R + f"[!] DNSdumpster API error: {data['error']}" + W)
                return self.live_subdomains

            # Process all record types
            for record_type in ['a', 'cname', 'mx', 'ns']:
                records = data.get(record_type, [])
                if not records:
                    continue
                    
                for record in records:
                    # Handle both string and dictionary record formats
                    if isinstance(record, dict):
                        host = record.get('host', '')
                    else:
                        host = str(record)
                        
                    if host and host.endswith(self.domain) and host != self.domain:
                        if host not in self.subdomains:
                            if self.verbose:
                                self.print_(G + f"[-] Found: {host}" + W)
                            self.subdomains.append(host)

            # Start validation of found subdomains
            threads = []
            for subdomain in self.subdomains:
                t = threading.Thread(target=self.check_host, args=(subdomain,))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

        except Exception as e:
            self.print_(R + f"[!] Error during enumeration: {str(e)}" + W)

        return self.live_subdomains

        # Validate found subdomains
        threads = []
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.check_host, args=(subdomain,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return self.live_subdomains

    # Los métodos de extracción web se han eliminado ya que ahora usamos solo la API


class Virustotal(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.virustotal.com/ui/domains/{domain}/subdomains'
        self.engine_name = "Virustotal"
        self.q = q
        super(Virustotal, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)
        return

    # the main send_req need to be rewritten
    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            self.print_(e)
            resp = None

        return self.get_response(resp)

    # once the send_req is rewritten we don't need to call this function, the stock one should be ok
    def enumerate(self):
        while self.url != '':
            resp = self.send_req(self.url)
            resp = json.loads(resp)
            if 'error' in resp:
                self.print_(R + "[!] Error: Virustotal probably now is blocking our requests" + W)
                break
            if 'links' in resp and 'next' in resp['links']:
                self.url = resp['links']['next']
            else:
                self.url = ''
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        #resp is already parsed as json
        try:
            for i in resp['data']:
                if i['type'] == 'domain':
                    subdomain = i['id']
                    if not subdomain.endswith(self.domain):
                        continue
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass


class ThreatCrowd(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.engine_name = "ThreatCrowd"
        self.q = q
        super(ThreatCrowd, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


class CrtSearch(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://crt.sh/?q=%25.{domain}'
        self.engine_name = "SSL Certificates"
        self.q = q
        super(CrtSearch, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<TD>(.*?)</TD>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = link.strip()
                subdomains = []
                if '<BR>' in link:
                    subdomains = link.split('<BR>')
                else:
                    subdomains.append(link)

                for subdomain in subdomains:
                    if not subdomain.endswith(self.domain) or '*' in subdomain:
                        continue

                    if '@' in subdomain:
                        subdomain = subdomain[subdomain.find('@')+1:]

                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception as e:
            print(e)
            pass

class PassiveDNS(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://api.sublist3r.com/search.php?domain={domain}'
        self.engine_name = "PassiveDNS"
        self.q = q
        super(PassiveDNS, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if not resp:
            return self.subdomains

        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            subdomains = json.loads(resp)
            for subdomain in subdomains:
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


class portscan():
    def __init__(self, subdomains, ports):
        self.subdomains = subdomains
        self.ports = ports
        self.lock = None

    def port_scan(self, host, ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                s.close()
            except Exception:
                pass
        self.lock.release()
        if len(openports) > 0:
            print("%s%s%s - %sFound open ports:%s %s%s%s" % (G, host, W, R, W, Y, ', '.join(openports), W))

    def run(self):
        self.lock = threading.BoundedSemaphore(value=20)
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))
            t.start()


def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    bruteforce_list = set()
    search_list = set()

    if is_windows:
        subdomains_queue = list()
    else:
        subdomains_queue = multiprocessing.Manager().list()

    # Check Bruteforce Status
    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    # Validate domain
    domain_check = re.compile(r"^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(R + "Error: Please enter a valid domain" + W)
        return []

    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://' + domain

    parsed_domain = urlparse.urlparse(domain)

    if not silent:
        print(B + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + W)

    if verbose and not silent:
        print(Y + "[-] verbosity is enabled, will show the subdomains results in realtime" + W)

    supported_engines = {'baidu': BaiduEnum,
                         'yahoo': YahooEnum,
                         'google': GoogleEnum,
                         'bing': BingEnum,
                         'ask': AskEnum,
                         'netcraft': NetcraftEnum,
                         'dnsdumpster': DNSdumpster,
                         'virustotal': Virustotal,
                         'threatcrowd': ThreatCrowd,
                         'ssl': CrtSearch,
                         'passivedns': PassiveDNS
                         }

    chosenEnums = []

    if engines is None:
        chosenEnums = [
            BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum,
            NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
            CrtSearch, PassiveDNS
        ]
    else:
        engines = engines.split(',')
        for engine in engines:
            if engine.lower() in supported_engines:
                chosenEnums.append(supported_engines[engine.lower()])

    # Start the engines enumeration
    enums = [enum(domain, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum in chosenEnums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if enable_bruteforce:
        if not silent:
            print(G + "[-] Starting bruteforce module now using subbrute.." + W)
        record_type = False
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
        resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
        process_count = threads
        output = False
        json_output = False
        bruteforce_list = subbrute.print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count, output, json_output, search_list, verbose)

    subdomains = search_list.union(bruteforce_list)

    if subdomains:
        subdomains = sorted(subdomains, key=subdomain_sorting_key)

        if savefile:
            write_file(savefile, subdomains)

        if not silent:
            print(Y + "[-] Total Unique Subdomains Found: %s" % len(subdomains) + W)

        if ports:
            if not silent:
                print(G + "[-] Start port scan now for the following ports: %s%s" % (Y, ports) + W)
            ports = ports.split(',')
            pscan = portscan(subdomains, ports)
            pscan.run()

        elif not silent:
            for subdomain in subdomains:
                print(G + subdomain + W)
    return subdomains


def interactive():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    engines = args.engines
    if verbose or verbose is None:
        verbose = True
    if args.no_color:
        no_color()
    banner()
    res = main(domain, threads, savefile, ports, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce, engines=engines)

if __name__ == "__main__":
    interactive()
