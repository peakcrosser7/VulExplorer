# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
import os.path
from urllib import parse

import scrapy
from scrapy.exporters import JsonItemExporter
from scrapy.http import TextResponse
from scrapy.pipelines.files import FilesPipeline

from crawl_vuls import config


class CrawlVulsFilePipeline(FilesPipeline):
    _target_domain = config.DOWNLOAD_DOMAIN

    def get_media_requests(self, item, info):
        i = 0
        for url in item['vul_file_urls']:
            yield scrapy.Request(url=parse.urljoin(self._target_domain, url), meta={
                'CVE_id': item['CVE_id'],
                'file_name': item['file_paths'][i].split('/')[-1],
                'is_fixed': False
            })
            i += 1
        i = 0
        for url in item['fixed_file_urls']:
            yield scrapy.Request(url=parse.urljoin(self._target_domain, url), meta={
                'CVE_id': item['CVE_id'],
                'file_name': item['file_paths'][i].split('/')[-1],
                'is_fixed': True
            })
            i += 1

    def file_path(self, request: TextResponse, response=None, info=None, *, item=None):
        dir_name = request.meta['CVE_id']
        file_name = request.meta['file_name']
        file_name += '#fixed' if request.meta['is_fixed'] else '#vul'
        return os.path.join(dir_name, file_name)


class CrawlVulsListPipeline:
    def __init__(self):
        if not os.path.exists(config.DATASET_STORE_DIR):
            os.makedirs(config.DATASET_STORE_DIR)
        vul_list_path = os.path.join(config.DATASET_STORE_DIR, config.VUL_LIST_FILE_NAME + '.json')

        self._file = open(vul_list_path, 'wb')
        self._exporter = JsonItemExporter(self._file)
        self._exporter.fields_to_export = [
            'CVE_id', 'CWE_id', 'vul_type', 'file_paths', 'affected_vers',
            'fixed_vers', 'vul_func', 'vul_desc'
        ]
        self._exporter.start_exporting()

    def process_item(self, item, spider):
        self._exporter.export_item(item)
        return item

    def close_spider(self, spider):
        self._exporter.finish_exporting()
        self._file.close()
