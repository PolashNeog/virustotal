# VirusTotal Public API Library

[![Build Status](https://travis-ci.org/jaystino/virustotal.svg?branch=master)](https://travis-ci.org/jaystino/virustotal)

#### Query the [VirusTotal](https://www.virustotal.com/#/home/url) API for URL reports. If no report exists for a given URL, the URL is automatically submitted for scanning and the report is fetched when complete.

#### This project assumes the use of VirusTotal's public API and limits the number of API calls to 4 per minute accordingly. Reconfigure as needed if using the private API (more info [here](https://www.virustotal.com/en/documentation/)).

#### VirusTotal public API documentation can be found [here](https://www.virustotal.com/en/documentation/public-api/).

#### Installation:

##### Fork repo, cd into project root, then...

```python
pip install pipenv
pipenv install
```

#### Use:

##### You can run from the command line inside the pipenv shell...

```python
# NOTE: no argparse integration yet, so execution controlled manually inside
# main statement in virustotal.py
pipenv shell
python virustotal.py
exit
```

##### or do the same on a single line (helpful if running as part of an automated workflow)...

```python
# See argparse comment above
pipenv run python virustotal.py
```

##### or configure and run however you seen fit.

#### Features coming soon...
* argparse for running from command line
* file hash scanning