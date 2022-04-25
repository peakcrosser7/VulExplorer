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
    file_paths = scrapy.Field()
    affected_vers = scrapy.Field()
    fixed_vers = scrapy.Field()
    vul_func = scrapy.Field()
    vul_desc = scrapy.Field()
    vul_file_urls = scrapy.Field()
    fixed_file_urls = scrapy.Field()
    lost_file = scrapy.Field()
    is_manual = scrapy.Field()
