# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
import os.path

from scrapy.exporters import JsonItemExporter

from crawl_vuls import config


class CrawlVulsListPipeline:
    def __init__(self):
        if not os.path.exists(config.DATASET_STORE_DIR):
            os.makedirs(config.DATASET_STORE_DIR)
        vul_list_path = os.path.join(config.DATASET_STORE_DIR, config.VUL_LIST_FILE_NAME + '.json')

        self._file = open(vul_list_path, 'wb')
        self._exporter = JsonItemExporter(self._file)
        self._exporter.fields_to_export = [
            'CVE_id', 'is_manual', 'CWE_id', 'vul_type', 'file_paths', 'affected_vers',
            'fixed_vers', 'vul_func', 'vul_desc',
        ]
        self._exporter.start_exporting()

    def process_item(self, item, spider):
        self._exporter.export_item(item)
        return item

    def close_spider(self, spider):
        self._exporter.finish_exporting()
        self._file.close()
