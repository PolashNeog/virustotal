from virustotal.src.virustotal import *
# from virustotal.secret_dev import *

class TestClass:

    inst = VirusTotal()
    url = "www.google.com"
    inst.add_resource(url, "url")

    def test_add_resource(self):
        """Test the proper instantiation of an Incident"""
        resource_attributes = [self.inst.incidents[0].name,
                               self.inst.incidents[0].category]

        assert resource_attributes == ["www.google.com", "url"]

    def test_api_key(self):
        """Test the public API key is valid"""
        params = {'apikey': vt_key,
                  'resource': self.inst.incidents[0].name,
                  'scan': 1}
        r = requests.get("https://www.virustotal.com/vtapi/v2/url/report",
                         params=params)
        result = r.json()["response_code"]

        assert result == 1
