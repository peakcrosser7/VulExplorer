# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CrawlVulsItem(scrapy.Item):
    CVE_id = scrapy.Field()
    CWE_id = scrapy.Field()
    vul_type = scrapy.Field()
    vul_desc = scrapy.Field()
    app_name = scrapy.Field()
    versions = scrapy.Field()
    func_name = scrapy.Field()
    file_paths = scrapy.Field()
    vul_file_urls = scrapy.Field()
    fixed_file_urls = scrapy.Field()
