#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/12/01 23:21
# @File   : cnvd.py
# -----------------------------------------------
# cnvd://www.cnvd.org.cn/
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
import re
import time
import os


class CNVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'CNVD'
        self.name_en = 'CNVD'
        self.home_page = 'https://www.cnvd.org.cn/'
        self.url_list = os.environ["URL_LIST"]
        self.url_cve = os.environ["URL_CVE"]


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self, limit = 6):
        params = {
            'length': limit,
            'start' : 0
        }

        response = requests.get(
            self.url_list,
            headers = self.headers(),
            params = params,
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            ids = re.findall(r'(CNVD-\d{4,6}-\d{3,6}|CNNVD-\d{4,6}-\d{3,6}|CICSVD-\d{4,6}-\d{3,6}|CVE-\d{4,6}-\d{3,6})', response.text)
            ids = list(set(ids))
            for id in ids :
                cve = self.to_cve(id)
                if cve.is_vaild():
                    cves.append(cve)
                    log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i] 服务器返回内容：[%s]' % (self.NAME_CH(), response.status_code,response.text))
        return cves


    def to_cve(self, id):
        cve = CVEInfo()
        cve.id = id
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + id
        self.get_cve_info(cve, cve.url)
        return cve


    def get_cve_info(self, cve, url):
        response = requests.get(
            url,
            headers = self.headers(),
            timeout = self.timeout
        )

        if response.status_code == 200:
            regex = r'<h1 .*?>(.*?)</h1>'
            title = re.findall(regex,response.text,re.S)[0].strip()
            public_time = re.findall(r'时间.*\s+(\d{2,4}-\d{1,2}-\d{1,2})\s+.*时间',response.text)[0].strip()
            cnvd_info = re.findall(r'漏洞描述\s+</span></div></div>(\s.*)',response.text)[0].strip()
            cve.title = title
            cve.time = public_time
            cve.info = cnvd_info

        time.sleep(2)

