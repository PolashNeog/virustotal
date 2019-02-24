# VirusTotal Public API Library

[![Build Status](https://travis-ci.org/jaystino/virustotal.svg?branch=master)](https://travis-ci.org/jaystino/virustotal)

#### Query the [VirusTotal v2.0](https://www.virustotal.com/#/home/url) API for URL reports. If no report exists for a given URL, the URL is automatically submitted for scanning and the report is fetched when complete.

#### This project assumes the use of VirusTotal's public API and limits the number of API calls to 4 per minute accordingly. Reconfigure as needed if using the private API (more info [here](https://www.virustotal.com/en/documentation/private-api/)).

#### VirusTotal public API documentation can be found [here](https://www.virustotal.com/en/documentation/public-api/).

___

#### Setup and Installation:

##### Follow [the instructions](https://www.virustotal.com/en/documentation/public-api/#) to create a free VirusTotal public API key.

##### Fork repo, cd into project root, then...

```python
pip install pipenv
pipenv install --ignore-pipfile
```

##### Add your API key to a secrets file (don't forget to add it to your .gitignore)...

```python
# secrets.py contents...

# VirusTotal API key
vt_key = "your_API_key"

```

##### ...or add your API key as an environment variable according to your OS (the same way you add items to your path).

___

#### Usage:

##### You can run from the command line inside the pipenv shell...

```python
pipenv shell
python virustotal.py -u http://www.someexample.com https://anotherexample.com
exit
```

##### ...or do the same on a single line (helpful if running in an automated workflow)...

```python
# See argparse comment above
pipenv run python virustotal.py -uf path/to/url/file.csv
```

##### ...or configure and run however you see fit.
