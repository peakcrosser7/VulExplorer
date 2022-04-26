import re
from typing import Optional, Tuple, List

import scrapy
from scrapy.http import TextResponse
from urllib import parse

from crawl_vuls import config
from crawl_vuls.items import CrawlVulsItem


class CrawlVulsSpider(scrapy.Spider):
    name = 'vuls_crawler'  # 爬虫名
    allowed_domains = config.TARGET_DOMAINS  # 限定爬取域名列表
    start_urls = [config.TARGET_URL]  # 爬取URL列表

    _vers_pattern = re.compile(r'Fixed in OpenSSL (\d\.\d\.\d[a-z]*)\s+\(Affected ([\da-z.\-,]+)\)')
    _func_pattern = re.compile(r'(\w+)\(?\)?\s+function\b')

    @staticmethod
    def _getStrOrEmpty(string: Optional[str]) -> str:
        return string if string else ""

    @staticmethod
    def _get_target_url(page: int) -> str:
        return "https://www.cvedetails.com/vulnerability-list.php?vendor_id=217&product_id=&version_id=&page={}" \
               "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0" \
               "&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=209" \
               "&sha=d709ee3c0dc47c3827b5990023842398148d082b".format(page)

    def parse(self, response: TextResponse, **kwargs):
        page_end = int(response.xpath(
            '//div[@class="paging"]/a[last()]/text()'
        ).get().strip())

        if 0 < config.PAGE_END < page_end:
            page_end = config.PAGE_END

        for i in range(1, page_end + 1):
            url = self._get_target_url(i)
            yield scrapy.Request(url=url, callback=self._parse_vul_info)

    def _parse_vul_info(self, response: TextResponse):
        for tr in response.xpath('//div[@id="searchresults"]/table/tr[@class="srrowns"]'):
            item = CrawlVulsItem()
            item['app_name'] = 'Openssl'
            item['is_manual'] = 0
            item['lost_file'] = False
            item['CVE_id'] = tr.xpath('./td[2]/a/text()').get().strip()
            item['CWE_id'] = self._getStrOrEmpty(tr.xpath('./td[3]/a/text()').get()).strip()
            item['vul_type'] = self._getStrOrEmpty(tr.xpath('./td[5]/text()').get()).split()
            url = 'https://www.cvedetails.com' + tr.xpath('./td[2]/a/@href').get()
            yield scrapy.Request(url=url, callback=self._parse_vul_detail,
                                 cb_kwargs=dict(item=item))

    @classmethod
    def _get_vul_vers(cls, vul_desc: str) -> Tuple[list, list]:
        res_it = cls._vers_pattern.finditer(vul_desc)
        fixed_vers, affected_vers = [], []
        for res in res_it:
            fixed_vers.append(res.group(1))
            affected_vers.append(res.group(2))
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
        item['vul_func'] = self._get_vul_func(desc)
        for ref_url in response.xpath('//table[@id="vulnrefstable"]/tr/td/a/@href').getall():
            if ref_url.startswith('https://git.openssl.org/'):
                yield scrapy.Request(url=ref_url, callback=self._parse_vul_git_page,
                                     cb_kwargs=dict(item=item))
                return

    def _parse_vul_git_page(self, response: TextResponse, item: CrawlVulsItem):
        file_paths = response.xpath('//table[@class="diff_tree"]/tr/td[1]/a/text()').getall()
        if not file_paths:
            return
        item['file_paths'] = file_paths
        item['vul_file_urls'] = []
        item['fixed_file_urls'] = []

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

    def _parse_vul_code_file(self, response: TextResponse, item: CrawlVulsItem, is_fixed: bool):
        url = response.xpath('//div[@class="page_path"]/a[last()]/@href').get()
        if is_fixed:
            item['fixed_file_urls'].append(url)
        else:
            item['vul_file_urls'].append(url)
        if len(item['fixed_file_urls']) == len(item['file_paths']):
            print(item['CVE_id'])
            yield item
