from typing import Optional

import scrapy
from scrapy.http import TextResponse

from crawl_vuls import config
from crawl_vuls.items import CrawlVulsItem


class CrawlVulsSpider(scrapy.Spider):
    name = 'vuls_crawler'  # 爬虫名
    allowed_domains = config.TARGET_DOMAINS  # 限定爬取域名列表
    _target_url = config.TARGET_URL
    start_urls = [_target_url]  # 爬取URL列表

    @staticmethod
    def _getStrOrEmpty(string: Optional[str]) -> str:
        return string if string else ""

    def parse(self, response: TextResponse, **kwargs):
        page_end = int(response.xpath(
            '//div[@class="paging"]/a[last()]/text()'
        ).get().strip())

        if 0 < config.PAGE_END < page_end:
            page_end = config.PAGE_END

        for i in range(1, page_end + 1):
            url = self._target_url + "&page=%s" % i
            yield scrapy.Request(url=url, callback=self._parse_vul_info)

    def _parse_vul_info(self, response: TextResponse):
        item = CrawlVulsItem()
        for tr in response.xpath('//div[@id="searchresults"]/table/tr[@class="srrowns"]'):
            item['app_name'] = 'Openssl'
            item['CVE_id'] = tr.xpath('./td[2]/a/text()').get().strip()
            item['CWE_id'] = self._getStrOrEmpty(tr.xpath('./td[3]/a/text()').get()).strip()
            item['vul_type'] = self._getStrOrEmpty(tr.xpath('./td[5]/text()').get()).split()
            url = 'https://www.cvedetails.com' + tr.xpath('./td[2]/a/@href').get()
            yield scrapy.Request(url=url, callback=self._parse_vul_detail,
                                 cb_kwargs=dict(item=item))

    def _parse_vul_detail(self, response: TextResponse, item: CrawlVulsItem):
        item['vul_desc'] = response.xpath('//div[@class="cvedetailssummary"]/text()').get().strip()
        for ref_url in response.xpath('//table[@id="vulnrefstable"]/tr/td/a/@href').getall():
            if ref_url.startswith('https://git.openssl.org/gitweb/'):
                yield scrapy.Request(url=ref_url, callback=self._parse_vul_codes,
                                     cb_kwargs=dict(item=item))
                return

    @staticmethod
    def _parse_vul_codes(response: TextResponse, item: CrawlVulsItem):
        item['file_paths'] = response.xpath('//table[@class="diff_tree"]/tr/td[1]/a/text()').getall()
        item['vul_file_urls'] = response.xpath(
            '//div[@class="patchset"]/div/div[@class="diff header"]/a[1]/@href'
        ).getall()
        item['fixed_file_urls'] = response.xpath(
            '//div[@class="patchset"]/div/div[@class="diff header"]/a[2]/@href'
        ).getall()
        yield item
