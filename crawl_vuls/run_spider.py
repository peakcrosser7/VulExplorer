from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

from utils.log import pinfo

if __name__ == '__main__':
    process = CrawlerProcess(get_project_settings())
    process.crawl('vuls_crawler')
    process.start()
    process.join()
    pinfo('crawling finished')
