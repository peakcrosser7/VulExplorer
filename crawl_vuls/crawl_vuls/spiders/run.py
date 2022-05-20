import os.path
import re
from typing import Optional, Tuple, List

import scrapy
from scrapy.http import TextResponse
from urllib import parse

from crawl_vuls import config
from crawl_vuls.items import CrawlVulsItem
from utils.log import pinfo


class CrawlVulsSpider(scrapy.Spider):
    name = 'vuls_crawler'  # 爬虫名
    allowed_domains = config.TARGET_DOMAINS  # 限定爬取域名列表
    start_urls = [config.TARGET_URL]  # 爬取URL列表

    # _vers_pattern = re.compile(r'Fixed in OpenSSL (\d\.\d\.\d[a-z]*)\s+\(Affected ([\da-z.\-,]+)\)')
    _vers_pattern = re.compile(r'(\d\.\d\.\d+) before (\d\.\d\.\d+[a-z]*)')
    _vers_pattern1 = re.compile(r'OpenSSL before (\d\.\d\.\d+[a-z]*)')
    _func_pattern = re.compile(r'(\w+)\(?\)?\s+function\b')

    @staticmethod
    def _getStrOrEmpty(string: Optional[str]) -> str:
        return string if string else ""

    @staticmethod
    def _get_target_url(target_url: str, page: int) -> str:
        if target_url == 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=217':
            return "https://www.cvedetails.com/vulnerability-list.php?vendor_id=217&product_id=&version_id=&page={}" \
                   "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0" \
                   "&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=209" \
                   "&sha=d709ee3c0dc47c3827b5990023842398148d082b".format(page)
        return 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=217&product_id=383&version_id=465603' \
               '&page={}&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0' \
               '&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0' \
               '&order=1&trc=69&sha=1d7cf8e188974f43c6579c4556ff85f5d9b797ae'.format(page)

    def parse(self, response: TextResponse, **kwargs):
        # url = "https://www.cvedetails.com/vulnerability-list/vendor_id-217/opov-1/Openssl.html"
        # yield scrapy.Request(url=url, callback=self._parse_vul_info)
        # return
        pinfo('start crawl vul dataset from url: %s' % config.TARGET_URL)

        page_end = int(response.xpath(
            '//div[@class="paging"]/a[last()]/text()'
        ).get().strip())

        if 0 < config.PAGE_END < page_end:
            page_end = config.PAGE_END
        page_start = config.PAGE_START if 0 < config.PAGE_START <= page_end else 1

        for i in range(page_start, page_end + 1):
            url = self._get_target_url(config.TARGET_URL, i)
            yield scrapy.Request(url=url, callback=self._parse_vul_info)

    def _parse_vul_info(self, response: TextResponse):
        for tr in response.xpath('//div[@id="searchresults"]/table/tr[@class="srrowns"]'):
            item = CrawlVulsItem()
            item['app_name'] = 'Openssl'
            item['vul_info'] = []
            item['keywords'] = []
            item['is_manual'] = 0
            item['vul_file_cnt'] = 0
            item['fixed_file_cnt'] = 0

            item['CVE_id'] = tr.xpath('./td[2]/a/text()').get().strip().lstrip('CVE-')
            item['CWE_id'] = self._getStrOrEmpty(tr.xpath('./td[3]/a/text()').get()).strip()
            item['vul_type'] = self._getStrOrEmpty(tr.xpath('./td[5]/text()').get()).split()
            url = 'https://www.cvedetails.com' + tr.xpath('./td[2]/a/@href').get()
            yield scrapy.Request(url=url, callback=self._parse_vul_detail,
                                 cb_kwargs=dict(item=item))

    @classmethod
    def _get_vul_vers(cls, vul_desc: str) -> Tuple[list, list]:
        fixed_vers, affected_vers = [], []
        res_it = cls._vers_pattern1.search(vul_desc)
        if res_it:
            fixed_vers.append(res_it.group(1))
            affected_vers.append('before ' + res_it.group(1))

        res_it = cls._vers_pattern.finditer(vul_desc)
        for res in res_it:
            if 'a' <= res.group(2)[-1] <= 'z':
                fixed_vers.append(res.group(2))
                s = list(res.group(2))
                s[-1] = chr(ord(s[-1]) - 1)
                affected_vers.append(res.group(1) + "-" + "".join(s))

        return fixed_vers, affected_vers

    @classmethod
    def _get_vul_func(cls, vul_desc: str) -> set:
        func_set = set()
        res_it = cls._func_pattern.finditer(vul_desc)
        for res in res_it:
            func_set.add(res.group(1))
        return func_set

    def _parse_vul_detail(self, response: TextResponse, item: CrawlVulsItem):
        desc = response.xpath('//div[@class="cvedetailssummary"]/text()').get().strip()
        item['vul_desc'] = desc
        item['fixed_vers'], item['affected_vers'] = self._get_vul_vers(desc)
        # item['vul_func'] = self._get_vul_func(desc)
        for ref_url in response.xpath('//table[@id="vulnrefstable"]/tr/td/a/@href').getall():
            if ref_url.startswith('https://git.openssl.org/'):
                yield scrapy.Request(url=ref_url, callback=self._parse_vul_git_page,
                                     cb_kwargs=dict(item=item))
                return

    def _parse_vul_git_page(self, response: TextResponse, item: CrawlVulsItem):
        file_paths = response.xpath('//table[@class="diff_tree"]/tr/td[1]/a/text()').getall()
        if not file_paths:
            return
        for path in file_paths:
            vul_dict = {'file_path': path, 'funcs': []}
            item['vul_info'].append(vul_dict)

        if response.xpath('//table[@class="diff_tree"]/tr/td[3]/a[1]/text()').get().strip() == 'diff':
            for diff_url in response.xpath('//table[@class="diff_tree"]/tr/td[3]/a[1]/@href').getall():
                url = parse.urljoin(config.DOWNLOAD_DOMAIN, diff_url)
                yield scrapy.Request(url=url, callback=self._parse_vul_diff_page,
                                     cb_kwargs=dict(item=item))
        else:
            for vul_path in response.xpath(
                    '//div[@class="patchset"]/div/div[@class="diff header"]/a[1]/@href'
            ).getall():
                url = parse.urljoin(config.DOWNLOAD_DOMAIN, vul_path)
                yield scrapy.Request(url=url, callback=self._parse_vul_code_file,
                                     cb_kwargs=dict(item=item, is_fixed=False))
            for fixed_path in response.xpath(
                    '//div[@class="patchset"]/div/div[@class="diff header"]/a[2]/@href'
            ).getall():
                url = parse.urljoin(config.DOWNLOAD_DOMAIN, fixed_path)
                yield scrapy.Request(url=url, callback=self._parse_vul_code_file,
                                     cb_kwargs=dict(item=item, is_fixed=True))

    def _parse_vul_diff_page(self, response: TextResponse, item: CrawlVulsItem):
        vul_path = response.xpath(
            '//div[@class="patchset"]/div/div[@class="diff header"]/a[1]/@href'
        ).get()
        url = parse.urljoin(config.DOWNLOAD_DOMAIN, vul_path)
        yield scrapy.Request(url=url, callback=self._parse_vul_code_file,
                             cb_kwargs=dict(item=item, is_fixed=False))

        fixed_path = response.xpath(
            '//div[@class="patchset"]/div/div[@class="diff header"]/a[2]/@href'
        ).get()
        url = parse.urljoin(config.DOWNLOAD_DOMAIN, fixed_path)
        yield scrapy.Request(url=url, callback=self._parse_vul_code_file,
                             cb_kwargs=dict(item=item, is_fixed=True))

    @staticmethod
    def _save_codes(file_name: str, cve_id: str, codes: List[str]):
        dir_path = os.path.join(config.CODE_FILE_STORE_DIR, cve_id)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        file_path = os.path.join(dir_path, file_name)
        with open(file_path, 'w') as wf:
            for line in codes:
                wf.write(line.replace(u'\xa0', u' '))
                wf.write('\n')
        # print(cve_id, ' ', file_name)

    def _parse_vul_code_file(self, response: TextResponse, item: CrawlVulsItem, is_fixed: bool):
        file_name = ''
        if is_fixed:
            file_name += 'fixed#'
            item['fixed_file_cnt'] += 1
        else:
            file_name += 'vul#'
            item['vul_file_cnt'] += 1
        file_name += response.xpath('//div[@class="page_path"]/a[last()]/text()').get().strip()

        codes = response.xpath('//div[@class="page_body"]/div[@class="pre"]/text()').getall()
        self._save_codes(file_name, item['CVE_id'], codes)

        if item['fixed_file_cnt'] == len(item['vul_info']) \
                and item['vul_file_cnt'] == len(item['vul_info']):
            pinfo('crawled a vulnerability: %s' % 'CVE-' + item['CVE_id'])
            yield item
