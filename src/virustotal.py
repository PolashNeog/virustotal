"""

"""
import requests
from pprint import pprint
from secret import *


class Resource:
    def __init__(self):
        self.items = {}
        # self.name = None
        # self.category = None
        # self.positives = None
        # self.scan_id = None
        # self.scan_date = None

    def add_resource(self, resource, category):
        """

        :param resource:
        :param category:
        :return:
        """
        if category in self.items:
            self.items[category].append(resource)
        else:
            self.items[category] = [resource]


class VirusTotal:
    def __init__(self):
        self.base_url = "https://www.virustotal.com/vtapi/v2/"
        self.items = {}
        self.results = {}

    def add_resource(self, resource, category):
        """

        :param resource:
        :param category:
        :return:
        """
        if category in self.items:
            self.items[category].append(resource)
        else:
            self.items[category] = [resource]

    def build_dict(self, resp):
        """

        :return:
        """
        # item_dict = {}s
        if "url" in resp:
            if resp["response_code"] == 1:
                self.results[resp["url"]] = {"category": "url",
                                        "postives": resp["positives"],
                                        "scan_id": resp["scan_id"],
                                        "scan_date": resp["scan_date"]}
            else:
                self.results[resp["url"]] = {"category": "url",
                                             "verbose_msg": resp["verbose_msg"]}

        if "file" in resp:
            pass
        if "file_hash" in resp:
            pass

    def scan_url(self, url):
        """

        :param url:
        :return:
        """
        params = {"apikey": vt_key,
                  "resource": url,
                  "scan": 1}
        req_url = self.base_url + "url/report"
        response = requests.get(req_url, params=params)

        pprint(response.json())
        return response.json()


# EXAMPLE RESPONSE:
# {
# 'response_code': 1,
# 'verbose_msg': 'Scan finished, scan information embedded in this object',
# 'scan_id': '1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1390467782',
# 'permalink': 'https://www.virustotal.com/url/__urlsha256__/analysis/1390467782/',
# 'url': 'http://www.virustotal.com/',
# 'scan_date': '2014-01-23 09:03:02',
# 'filescan_id': null,
# 'positives': 0,
# 'total': 51,
# 'scans': {
#     'CLEAN MX': {
#         'detected': false,
#         'result': 'clean site'
#     },
#     'MalwarePatrol': {
#         'detected': false,
#         'result': 'clean site'
#     }
# }
# }


if __name__ == '__main__':


    # batch = VirusTotal()
    #
    # batch.add_item("www.google.com", "url")
    # batch.add_item("www.yahoo.com", "url")
    # batch.add_item("danger.exe", "file")

    # print(batch.items)

    batch = VirusTotal()
    batch.add_resource("ogle", "url")
    batch.add_resource("www.yahoo.com", "url")
    # batch.add_resource("danger.exe", "file")
    pprint(batch.items)

    for i in batch.items["url"]:
        resp = batch.scan_url(i)
        batch.build_dict(resp)

    print("############")
    pprint(batch.results)
