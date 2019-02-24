"""Tests for virustotal.py"""
from virustotal.src.virustotal import *

vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
vt_key = os.environ["VTKEY"]

class TestClass:

    def test_create_ScanBatch_instance(self):
        """ScanBatch initiates a class object"""
        inst = ScanBatch("https://www.google.com")
        assert type(inst) == ScanBatch

    def test_api_key(self):
        """VT http request is valid"""
        inst = ScanBatch("https://www.yahoo.com")
        params = {'apikey': vt_key,
                  'resource': inst,
                  'scan': 1}
        r = requests.get(vt_url, params=params)
        assert r.status_code == requests.codes.ok

    def test_invalid_url_request(self):
        """Request with invalid URL returns descriptive error message"""
        inst = ScanBatch("gogles")
        params = {'apikey': vt_key,
                  'resource': inst,
                  'scan': 1}
        r = requests.get(vt_url, params=params)
        result = r.json()
        assert result["verbose_msg"] == "Invalid URL, the scan request was not queued"

    def test_valid_url_request(self):
        """Request with valid URL returns valid (affirmative) response code"""
        inst = ScanBatch("https://www.amazon.com")
        params = {'apikey': vt_key,
                  'resource': inst,
                  'scan': 1}
        r = requests.get(vt_url, params=params)
        result = r.json()["response_code"]
        assert result == 1
