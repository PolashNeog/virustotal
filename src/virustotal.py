"""

"""
import sys
import time
import requests
import datetime
from pprint import pprint
from ratelimit import limits, sleep_and_retry
from secret import *


class Incident:
    def __init__(self, name, category):
        self.name = name
        self.category = category
        self.scan_complete = False
        self.scan_id = None
        self.scan_date = None
        self.positives = None
        self.scan_count = None
        self.error = None

    def __repr__(self):
        return self.name


class VirusTotal:
    def __init__(self):
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        self.incidents = []

    def add_resource(self, resource, category):
        """Creates a new Incident class object and adds it to the list of incidents.

        :param resource: url of filename
        :param category: category of resource, eg 'url' or 'file'
        """
        incident = Incident(resource, category)
        self.incidents.append(incident)

    @sleep_and_retry
    @limits(calls=4, period=61)
    def scan_url(self, incident):
        """Queries the VT API for a given URL. If no report found, submits URL for
        scanning.

        :param incident: an Incident class URL
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
            countdown(60)
            self.scan_url(incident)

        else:
            # TODO: raise JSONDecodeError("Expecting value", s, err.value) from None
            resp = r.json()

            if resp['response_code'] == -1:
                incident.scan_complete = True
                incident.scan_date = datetime.datetime.today().strftime('%Y-%m-%d')
                incident.error = resp['verbose_msg']
                pprint(resp[0])
                return

            elif 'positives' in resp:
                incident.scan_complete = True
                incident.scan_id = resp['scan_id']
                incident.scan_date = resp['scan_date']
                incident.positives = resp['positives']
                incident.scan_count = resp['total']
                print('*************************', resp['scan_date'])
                pprint(r.json())
                return

            else:
                # incident.scan_id = resp['scan_id']
                self.scan_url(url)

                pprint(r.json())
            return

    def build_result_dict(self):
        """Builds and prints dictionary object for each incident."""
        result = {'incident': None,
                  'scan_count': None,
                  'positives': None,
                  'scan_date': None,
                  'scan_complete': False,
                  'error': None
                  }

        for i in self.incidents:
            result['incident'] = i.name
            result['scan_count'] = i.scan_count
            result['scan_complete'] = i.scan_complete
            result['scan_date'] = i.scan_date
            result['positives'] = i.positives
            result['error'] = i.error
            result['scan_id'] = i.scan_id
            print('')
            pprint(result)


def countdown(duration):
    """Prints countdown to stdout.

    :param duration: time in seconds
    """
    for i in range(duration, 0, -1):
        sys.stdout.write('\r')
        sys.stdout.write(f'{i} seconds remaining')
        sys.stdout.flush()
        time.sleep(1)


if __name__ == '__main__':

    batch = VirusTotal()
    # batch.add_resource('ogle', 'url')
    batch.add_resource('435345wbungeeeokok.com', 'url')
    batch.add_resource('www.pokokoktlyye.com', 'url')
    batch.add_resource('www.breeeeeetyo.com', 'url')
    # batch.add_resource('www.toggegole.com', 'url')
    # batch.add_resource('www.reawwwmamamoo.com', 'url')
    # batch.add_resource('www.nytwe432sfgrtimessss.com', 'url')
    # batch.add_resource('danger.exe', 'file')

    start = time.perf_counter()

    urls = [i for i in batch.incidents if i.category == 'url']
    print('URLS:', urls)

    for url in urls:
        batch.scan_url(url)
        print(time.perf_counter() - start)

    print('\nFINAL RESULTS FROM BATCH:')
    batch.build_result_dict()
