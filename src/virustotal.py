"""

"""
import requests
from pprint import pprint
from ratelimit import limits, sleep_and_retry
import time
from secret import *
from multiprocessing.pool import ThreadPool


class Incident:
    def __init__(self, item, category, scan_id=None, scan_date=None, positives=None,
                 error=None):
        self.item = item
        # self.name = None
        self.category = category
        self.scan_id = scan_id
        self.scan_date = scan_date
        self.positives = positives
        self.error = error
        # self.positives = None

        # self.scan_date = None

    def __repr__(self):
        return self.item

    def add_resource(self, resource, category):
        '''

        :param resource:
        :param category:
        :return:
        '''
        if category in self.items:
            self.items[category].append(resource)
        else:
            self.items[category] = [resource]


class VirusTotal:
    def __init__(self):
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        self.incidents = []


        self.items = {}
        self.results = {}
        self.rescans = {}
        self.errors = {}

    def add_resource_og(self, resource, category):
        """

        :param resource:
        :param category:
        :return:
        """
        if category in self.items:
            self.items[category].append(resource)
        else:
            self.items[category] = [resource]

    def add_resource(self, resource, category):
        """

        :param resource:
        :param category:
        :return:
        """
        incident = Incident(resource, category)
        self.incidents.append(incident)

    def build_dict(self, url, resp):
        """

        :return:
        """
        # item_dict = {}s
        if resp['response_code'] == 1:
            if 'url' in resp:
                self.results[resp['url']] = {'category': 'url',
                                             'postives': resp['positives'],
                                             'scan_id': resp['scan_id'],
                                             'scan_date': resp['scan_date']}
            elif 'file' in resp:
                pass

            elif 'file_hash' in resp:
                pass

            else:
                print("WHAT WENT WRONG??")
                # self.results[resp['url']] = {'category': 'url',
                #                              'verbose_msg': resp['verbose_msg']}
        else:
            if 'Invalid URL' in resp['verbose_msg']:
                self.results[url] = {'category': 'url',
                                             'verbose_msg': resp['verbose_msg']}

    @sleep_and_retry
    @limits(calls=4, period=61)
    def scan_url(self, url, id=None):
        """
        """
        if id:
            params = {'apikey': vt_key,
                      'resource': id,
                      'scan': 1}
        else:
            params = {'apikey': vt_key,
                      'resource': url,
                      'scan': 1}

        req_url = self.base_url + 'url/report'
        r = requests.get(req_url, params=params)
        resp = r.json()

        # if r.status_code != 200:
        #     self.errors[url] = resp['verbose_mssg']
            # raise Exception(f'API response: {r.status_code}')

        if resp['response_code'] == -1:
            url.error = resp['verbose_msg']

        elif 'positives' in resp:
            if url in self.rescans:
                if self.rescans[url]['resolved'] == False:
                    self.rescan(url, id)
            else:
                self.build_dict(url, resp)

        else:
            # save the scan id.
            try:
                self.rescans[url] = {'scan_id': resp['scan_id'], 'resolved': False}
            except KeyError:
                print('key error:', resp)


        pprint(r.json())
        return resp

    def rescan(self, url, id):
        resp = self.scan_url(url, id)
        if 'positives' in resp:
            self.rescans[url]['resolved'] = True
            self.build_dict(url, resp)
        return


@sleep_and_retry
@limits(calls=2, period=10)
def test_the_limit(count, timer):
    print(f'HEREEEEE: {count} at time: {time.perf_counter() - timer}')


if __name__ == '__main__':

    batch = VirusTotal()
    # batch.add_resource('ogle', 'url')
    batch.add_resource('www.yahttdfs1234go.com', 'url')
    batch.add_resource('www.pooer1234dgtle.edu', 'url')
    batch.add_resource('www.brae412wrdsgtyao.com', 'url')
    batch.add_resource('www.tot432wersfgtototole.com', 'url')
    batch.add_resource('www.reaw324ersfgtmamamoo.com', 'url')
    batch.add_resource('www.nytwe432sfgrtimessss.com', 'url')
    # batch.add_resource('danger.exe', 'file')
    # print('items:', batch.items)
    # exit()

    count = 1
    start = time.perf_counter()

    urls = [i for i in batch.incidents if i.category == 'url']
    print('URLS:', urls)
    for url in urls:
        if count % 4 == 0:
            print('API limit (4 calls/m) reached')
        print(f'############# count: {count}')
        batch.scan_url(url.item)
        print(time.perf_counter() - start)
        count += 1

    exit()

    print('batch.rescans starting len:', len(batch.rescans))
    pprint(batch.rescans)

    if batch.rescans:
        for i in batch.rescans:
            if batch.rescans[i]['resolved'] is False:
                print('happening before above compeletes???')

                if count % 4 == 0:
                    print('API limit (4 calls/m) reached')
                else:
                    print(f'############# count: {count}')

                batch.scan_url(i, batch.rescans[i])
                print(time.perf_counter() - start)
                print('is self.rescans shrinking???', len(batch.rescans))
                count += 1

    exit()
    url1 = {'response_code': -1,
            'verbose_msg': 'Invalid URL, the scan request was not queued'}
    url2 = {'filescan_id': None,
            'permalink': 'https://www.virustotal.com/url/ed91698b5823a5e4424726955dd3fd437d9cfdc46f7b8988cded5da779cc7483/analysis/1548440250/',
            'positives': 0,
            'resource': 'www.yahoo.com',
            'response_code': 1,
            'scan_date': '2019-01-25 18:17:30',
            'scan_id': 'ed91698b5823a5e4424726955dd3fd437d9cfdc46f7b8988cded5da779cc7483-1548440250',
            'scans': {'ADMINUSLabs': {'detected': False, 'result': 'clean site'},
            'AegisLab WebGuard': {'detected': False, 'result': 'clean site'},
            'AlienVault': {'detected': False, 'result': 'clean site'},
            'Antiy-AVL': {'detected': False, 'result': 'clean site'},
            'AutoShun': {'detected': False, 'result': 'unrated site'},
            'Avira': {'detected': False, 'result': 'clean site'},
            'Baidu-International': {'detected': False, 'result': 'clean site'},
            'BitDefender': {'detected': False, 'result': 'clean site'},
            'Blueliv': {'detected': False, 'result': 'clean site'},
            'C-SIRT': {'detected': False, 'result': 'clean site'},
            'CLEAN MX': {'detected': False, 'result': 'clean site'},
            'Certly': {'detected': False, 'result': 'clean site'},
            'Comodo Site Inspector': {'detected': False, 'result': 'clean site'},
            'CyRadar': {'detected': False, 'result': 'clean site'},
            'CyberCrime': {'detected': False, 'result': 'clean site'},
            'DNS8': {'detected': False, 'result': 'clean site'},
            'Dr.Web': {'detected': False, 'result': 'clean site'},
            'ESET': {'detected': False, 'result': 'clean site'},
            'Emsisoft': {'detected': False, 'result': 'clean site'},
            'Forcepoint ThreatSeeker': {'detected': False,
                                       'result': 'clean site'},
           'Fortinet': {'detected': False, 'result': 'clean site'},
           'FraudScore': {'detected': False, 'result': 'clean site'},
           'FraudSense': {'detected': False, 'result': 'clean site'},
           'G-Data': {'detected': False, 'result': 'clean site'},
           'Google Safebrowsing': {'detected': False, 'result': 'clean site'},
           'K7AntiVirus': {'detected': False, 'result': 'clean site'},
           'Kaspersky': {'detected': False, 'result': 'clean site'},
           'Malc0de Database': {'detail': 'http://malc0de.com/database/index.php?search=www.yahoo.com',
                                'detected': False,
                                'result': 'clean site'},
           'Malekal': {'detected': False, 'result': 'clean site'},
           'Malware Domain Blocklist': {'detected': False,
                                        'result': 'clean site'},
           'MalwareDomainList': {'detail': 'http://www.malwaredomainlist.com/mdl.php?search=www.yahoo.com',
                                 'detected': False,
                                 'result': 'clean site'},
           'MalwarePatrol': {'detected': False, 'result': 'clean site'},
           'Malwarebytes hpHosts': {'detected': False, 'result': 'clean site'},
           'Malwared': {'detected': False, 'result': 'clean site'},
           'Netcraft': {'detected': False, 'result': 'unrated site'},
           'NotMining': {'detected': False, 'result': 'unrated site'},
           'Nucleon': {'detected': False, 'result': 'clean site'},
           'OpenPhish': {'detected': False, 'result': 'clean site'},
           'Opera': {'detected': False, 'result': 'clean site'},
           'PhishLabs': {'detected': False, 'result': 'unrated site'},
           'Phishtank': {'detected': False, 'result': 'clean site'},
           'Quttera': {'detected': False, 'result': 'suspicious site'},
           'Rising': {'detected': False, 'result': 'clean site'},
           'SCUMWARE.org': {'detected': False, 'result': 'clean site'},
           'SecureBrain': {'detected': False, 'result': 'clean site'},
           'Sophos': {'detected': False, 'result': 'unrated site'},
           'Spam404': {'detected': False, 'result': 'clean site'},
           'StopBadware': {'detected': False, 'result': 'unrated site'},
           'Sucuri SiteCheck': {'detected': False, 'result': 'clean site'},
           'Tencent': {'detected': False, 'result': 'clean site'},
           'ThreatHive': {'detected': False, 'result': 'clean site'},
           'Trustwave': {'detected': False, 'result': 'clean site'},
           'URLQuery': {'detected': False, 'result': 'unrated site'},
           'VX Vault': {'detected': False, 'result': 'clean site'},
           'Virusdie External Site Scan': {'detected': False,
                                           'result': 'clean site'},
           'Web Security Guard': {'detected': False, 'result': 'clean site'},
           'Yandex Safebrowsing': {'detail': 'http://yandex.com/infected?l10n=en&url=http://www.yahoo.com/',
                                   'detected': False,
                                   'result': 'clean site'},
           'ZCloudsec': {'detected': False, 'result': 'clean site'},
           'ZDB Zeus': {'detected': False, 'result': 'clean site'},
           'ZeroCERT': {'detected': False, 'result': 'clean site'},
           'Zerofox': {'detected': False, 'result': 'clean site'},
           'ZeusTracker': {'detail': 'https://zeustracker.abuse.ch/monitor.php?host=www.yahoo.com',
                           'detected': False,
                           'result': 'clean site'},
           'desenmascara.me': {'detected': False, 'result': 'clean site'},
           'malwares.com URL checker': {'detected': False,
                                        'result': 'clean site'},
           'securolytics': {'detected': False, 'result': 'clean site'},
           'zvelo': {'detected': False, 'result': 'clean site'}},
           'total': 66,
           'url': 'http://www.yahoo.com/',
           'verbose_msg': 'Scan finished, scan information embedded in this object'}

    batch.build_dict('ogle', url1)
    batch.build_dict('www.yahoo.com', url2)

    print('batch.results')
    pprint(batch.results)

    print('items:', batch.items)
