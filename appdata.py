#!/usr/bin/env python
###################################################################################
#                           Written by Wei, Hang                                  #
#                          weihang_hank@gmail.com                                 #
###################################################################################
"""
This module has the functions to retrieve the data from AppDynamics Controller
"""
import tkinter as tk
import tkinter.messagebox
import requests
import json
import base64
from credentials import *

URL_APP = APPD_URL + "/controller/rest/applications"


def get_basic_auth_str(username, password):
    temp_str = username + ':' + password
    # convert to bytes string
    bytesString = temp_str.encode(encoding="utf-8")
    # base64 encoding
    encodestr = base64.b64encode(bytesString)

    return 'Basic ' + encodestr.decode()


def Query(url, header):
    payload = {}
    _url = URL_APP + url
    return requests.request("GET", _url, headers=header, data=payload)
    # return requests.request("GET", URL_TMP, headers=header, data=payload)


def get_appdict(application):
    appdict = {}
    header = {}
    header['Authorization'] = get_basic_auth_str(APPD_LOGIN, APPD_PASS)
    apps = json.loads(Query("?output=JSON", header).text)
    for app in apps:
        if app["name"] == application:
            tiers = json.loads(Query("/" + application + "/tiers?output=JSON", header).text)
            for tier in tiers:
                nodes = json.loads(
                    Query("/" + application + "/tiers/" + tier["name"] + "/nodes?output=JSON", header).text)
                nodelist = []
                for node in nodes:
                    addresslist = node["ipAddresses"]["ipAddresses"]
                    nodelist.append(addresslist[len(addresslist)-1])
                appdict[tier["name"]] = nodelist
    if not appdict:
        tk.messagebox.showerror(title="Error",
                                message="Application {} doesn't exist!".format(application))
        exit(1)
    else:
        return appdict


def main():
    """
    This main function is just for test.
    """
    print('get_appdict(application):\n', get_appdict('courseback'))
    # print('get_rs(application):\n',get_rs(application))


if __name__ == '__main__':
    main()
