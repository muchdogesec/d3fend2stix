# d3fend2stix

## Before you begin

![](docs/ctibutler.png)

We host a full web API that includes all objects created by d3fend2stix, [CTIButler](https://www.ctibutler.com/).

## Overview

A command line tool that turns MITRE D3fend into STIX 2.1 Objects.

## Installing the script

To install d3fend2stix;

```shell
# clone the latest code
git clone https://github.com/muchdogesec/d3fend2stix
# create a venv
cd d3fend2stix
python3 -m venv d3fend2stix-venv
source d3fend2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

## Running the script

```shell
python3 d3fend2stix.py
```

## Mappings

Can be viewed under `docs/stix-mapping.md`.

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [MITRE d3fend site](https://d3fend.mitre.org/)