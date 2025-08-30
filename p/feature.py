from bs4 import BeautifulSoup
import requests 
from urllib.parse import urlparse
import whois 
from datetime import datetime
from googlesearch import search
from dateutil.parser import parse as date_parse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            print(f"Error fetching URL: {e}")

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL: {e}")

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print(f"Error fetching WHOIS information: {e}")

    def getFeaturesList(self):
        features = []
        features.append(self.using_ip())
        features.append(self.long_url())
        features.append(self.short_url())
        features.append(self.symbol())
        features.append(self.redirecting())
        features.append(self.prefix_suffix())
        features.append(self.sub_domains())
        features.append(self.https())
        features.append(self.domain_reg_len())
        features.append(self.favicon())
        features.append(self.non_std_port())
        features.append(self.https_domain_url())
        features.append(self.request_url())
        features.append(self.anchor_url())
        features.append(self.links_in_script_tags())
        features.append(self.server_form_handler())
        features.append(self.info_email())
        features.append(self.abnormal_url())
        features.append(self.website_forwarding())
        features.append(self.status_bar_cust())
        features.append(self.disable_right_click())
        features.append(self.using_popup_window())
        features.append(self.iframe_redirection())
        features.append(self.age_of_domain())
        features.append(self.dns_recording())
        features.append(self.website_traffic())
        features.append(self.page_rank())
        features.append(self.google_index())
        features.append(self.links_pointing_to_page())
        features.append(self.stats_report())
        return features

    def using_ip(self):
        return 1 if any(char.isdigit() for char in self.domain) else 0

    def long_url(self):
        return 1 if len(self.url) >= 54 else 0

    def short_url(self):
        return 1 if len(self.url) < 27 else 0

    def symbol(self):
        symbols = ['@', '-', '?', '=', '&']
        return sum(1 for char in self.url if char in symbols)

    def redirecting(self):
        if self.response and hasattr(self.response, 'history'):
            return 1 if len(self.response.history) >= 1 else 0
        else:
            return 0

    def prefix_suffix(self):
        return 1 if '-' in self.urlparse.netloc else 0

    def sub_domains(self):
        return len(self.urlparse.netloc.split('.')) - 2

    def https(self):
        return 1 if self.urlparse.scheme == 'https' else 0

    def domain_reg_len(self):
        try:
            expiration_date = self.whois_response.expiration_date
            today = datetime.now()
            registration_length = (expiration_date - today).days
            return 1 if registration_length <= 365 else 0
        except Exception as e:
            print(f"Error calculating domain registration length: {e}")
            return 0

    def favicon(self):
        try:
            link = self.soup.find('link', rel='shortcut icon') or self.soup.find('link', rel='icon')
            href = link['href']
            return 0 if '.ico' in href else 1
        except Exception as e:
            print(f"Error extracting favicon information: {e}")
            return 1

    def non_std_port(self):
        return 1 if self.urlparse.port else 0

    def https_domain_url(self):
        return 1 if self.urlparse.netloc.startswith('https') else 0

    def request_url(self):
        try:
            for tag in self.soup.find_all('form', action=True):
                action = tag['action']
                if action and 'http' in action:
                    return 1
            return 0
        except Exception as e:
            print(f"Error extracting request URL information: {e}")
            return 0

    def anchor_url(self):
        try:
            for tag in self.soup.find_all('a', href=True):
                href = tag['href']
                if href and 'http' in href:
                    return 1
            return 0
        except Exception as e:
            print(f"Error extracting anchor URL information: {e}")
            return 0

    def links_in_script_tags(self):
        try:
            for tag in self.soup.find_all('script', src=True):
                src = tag['src']
                if src and 'http' in src:
                    return 1
            return 0
        except Exception as e:
            print(f"Error extracting links in script tags information: {e}")
            return 0

    def server_form_handler(self):
        try:
            for tag in self.soup.find_all('form', action=True):
                action = tag['action']
                if action and 'mailto' in action:
                    return 1
            return 0
        except Exception as e:
            print(f"Error extracting server form handler information: {e}")
            return 0

    def info_email(self):
        try:
            for tag in self.soup.find_all('a', href=True):
                href = tag['href']
                if href and 'mailto:' in href:
                    return 1
            return 0
        except Exception as e:
            print(f"Error extracting info email information: {e}")
            return 0

    def abnormal_url(self):
        try:
            return 1 if '//' in self.urlparse.path else 0
        except Exception as e:
            print(f"Error checking abnormal URL: {e}")
            return 0

    def website_forwarding(self):
        try:
            for tag in self.soup.find_all('meta', http_equiv=True):
                if tag['http-equiv'] == 'refresh' and 'http' in tag['content']:
                    return 1
            return 0
        except Exception as e:
            print(f"Error detecting website forwarding: {e}")
            return 0

    def status_bar_cust(self):
        try:
            for tag in self.soup.find_all('script', src=True):
                src = tag['src']
                if src and 'onmouseover' in src:
                    return 1
            return 0
        except Exception as e:
            print(f"Error detecting status bar customization: {e}")
            return 0

    def disable_right_click(self):
        try:
            for tag in self.soup.find_all('body', oncontextmenu=True):
                return 1
            return 0
        except Exception as e:
            print(f"Error detecting disable right click: {e}")
            return 0

    def using_popup_window(self):
        try:
            for tag in self.soup.find_all('script', src=True):
                src = tag['src']
                if src and 'window.open' in src:
                    return 1
            return 0
        except Exception as e:
            print(f"Error detecting popup window usage: {e}")
            return 0

    def iframe_redirection(self):
        try:
            for tag in self.soup.find_all('iframe', src=True):
                src = tag['src']
                if src and 'http' in src:
                    return 1
            return 0
        except Exception as e:
            print(f"Error detecting iframe redirection: {e}")
            return 0

    def age_of_domain(self):
        try:
            creation_date = self.whois_response.creation_date
            today = datetime.now()
            age_of_domain = (today - creation_date).days
            return 1 if age_of_domain <= 365 else 0
        except Exception as e:
            print(f"Error calculating age of domain: {e}")
            return 0

    def dns_recording(self):
        try:
            return 1 if self.whois_response.name_servers else 0
        except Exception as e:
            print(f"Error checking DNS recording: {e}")
            return 0

    def website_traffic(self):
        try:
            for result in search(self.domain, num=10, stop=1):
                return 1 if result else 0
        except Exception as e:
            print(f"Error checking website traffic: {e}")
            return 0

    def page_rank(self):
        try:
            for result in search(self.domain, num=10, stop=1):
                return 1 if 'rank' in result else 0
        except Exception as e:
            print(f"Error checking page rank: {e}")
            return 0

    def google_index(self):
        try:
            for result in search(self.domain, num=10, stop=1):
                return 1 if 'https://www.google.com/' in result else 0
        except Exception as e:
            print(f"Error checking Google index: {e}")
            return 0

    def links_pointing_to_page(self):
        try:
            return len(self.soup.find_all('a', href=self.url)) or len(self.soup.find_all('img', src=self.url))
        except Exception as e:
            print(f"Error checking links pointing to page: {e}")
            return 0

    def stats_report(self):
        try:
            for tag in self.soup.find_all('meta', name=True):
                if tag['name'] == 'alexa':
                    return 1
            return 0
        except Exception as e:
            print(f"Error checking stats report: {e}")
            return 0
