"""

"""
import requests
from pprint import pprint
from ratelimit import limits, sleep_and_retry
import time
from secret import *

# TODO: Finish docstrings


class Incident:
    def __init__(self, name, category, scan_id=None, scan_date=None, positives=None,
                 scan_count=None, error=None):
        self.name = name
        self.category = category
        self.scan_complete = False
        self.scan_id = scan_id
        self.scan_date = scan_date
        self.positives = positives
        self.scan_count = scan_count
        self.error = error

    def __repr__(self):
        return self.name


class VirusTotal:
    def __init__(self):
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        self.incidents = []

    def add_resource(self, resource, category):
        """

        :param resource: url of filename
        :param category: category of resource, eg 'url' or 'file'
        """
        incident = Incident(resource, category)
        self.incidents.append(incident)

    @sleep_and_retry
    @limits(calls=4, period=61)
    def scan_url(self, url):
        """
        """
        if url.scan_id:
            params = {'apikey': vt_key,
                      'resource': url.scan_id,
                      'scan': 1}
        else:
            params = {'apikey': vt_key,
                      'resource': url.name,
                      'scan': 1}

        req_url = self.base_url + 'url/report'
        r = requests.get(req_url, params=params)

        if r.status_code == 204:
            print('VT public API rate limit reached. Automatic retry in 60 seconds.')
            time.sleep(60)
            # TODO: ADD COUNTDOWN TIMER
            self.scan_url(url)

        # TODO: 'raise JSONDecodeError("Expecting value", s, err.value) from None'
        resp = r.json()

        if resp['response_code'] == -1:
            url.scan_complete = True
            url.error = resp['verbose_msg']

        elif 'positives' in resp:
            url.scan_complete = True
            url.scan_id = resp['scan_id']
            url.scan_date = resp['scan_date']
            url.positives = resp['positives']
            url.scan_count = resp['total']

        else:
            url.scan_id = resp['scan_id']
            self.rescan(url.name, url.scan_id)

        pprint(r.json())
        return resp

    def rescan(self, incident, id):
        """

        :param incident:
        :param id:
        """
        resp = self.scan_url(incident, id)
        if 'positives' in resp:
            url.scan_complete = True
            url.scan_date = resp['scan_date']
            url.positives = resp['positives']
            url.scan_count = resp['scan_count']
        return

    def build_result_dict(self):
        """
        """
        result = {'incident': None,
                  'scan_count': None,
                  'positives': None,
                  'scan_date': None,
                  'scan_complete': 'Nope',
                  'error': None
                  }

        for i in self.incidents:
            result['incident'] = i.name
            result['scan_count'] = i.scan_count
            result['scan_complete'] = i.scan_complete
            try:
                result['positives']: i.positives
                result['scan_date']: i.scan_date
            # TODO: catch except type
            except:
                result['error'] = i.error
            print('')
            pprint(result)


# @sleep_and_retry
# @limits(calls=2, period=10)
# def test_the_limit(count, timer):
#     print(f'HEREEEEE: {count} at time: {time.perf_counter() - timer}')


if __name__ == '__main__':

    batch = VirusTotal()
    batch.add_resource('ogle', 'url')
    batch.add_resource('www.yahttdfs1234go.com', 'url')
    batch.add_resource('www.pooertrytryr1234dgtle.edu', 'url')
    batch.add_resource('www.brae412wrdsgtyao.com', 'url')
    batch.add_resource('www.tot432wersfgtototole.com', 'url')
    batch.add_resource('www.reaw324ersfgtmamamoo.com', 'url')
    batch.add_resource('www.nytwe432sfgrtimessss.com', 'url')
    # batch.add_resource('danger.exe', 'file')

    count = 1
    start = time.perf_counter()

    urls = [i for i in batch.incidents if i.category == 'url']
    print('URLS:', urls)

    for url in urls:
        if count % 4 == 0:
            print('API limit (4 calls/m) reached')
        print(f'############# count: {count}')
        batch.scan_url(url)
        print(time.perf_counter() - start)
        count += 1

    print('\nFINAL RESULTS FROM BATCH:')
    batch.build_result_dict()
    exit()

    # print('batch.rescans starting len:', len(batch.rescans))
    # pprint(batch.rescans)

    # if batch.rescans:
    #     for i in batch.rescans:
    #         if batch.rescans[i]['resolved'] is False:
    #             print('happening before above compeletes???')
    #
    #             if count % 4 == 0:
    #                 print('API limit (4 calls/m) reached')
    #             else:
    #                 print(f'############# count: {count}')
    #
    #             batch.scan_url(i, batch.rescans[i])
    #             print(time.perf_counter() - start)
    #             print('is self.rescans shrinking???', len(batch.rescans))
    #             count += 1

    url1 = {'response_code': -1,
            'verbose_msg': 'Invalid URL, the scan request was not queued'}
