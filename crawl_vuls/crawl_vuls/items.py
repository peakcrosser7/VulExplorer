# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CrawlVulsItem(scrapy.Item):
    app_name = scrapy.Field()
    CVE_id = scrapy.Field()
    CWE_id = scrapy.Field()
    vul_type = scrapy.Field()
    vul_info = scrapy.Field()
    keywords = scrapy.Field()
    affected_vers = scrapy.Field()
    fixed_vers = scrapy.Field()
    vul_desc = scrapy.Field()
    is_manual = scrapy.Field()
    vul_file_cnt = scrapy.Field()
    fixed_file_cnt = scrapy.Field()
