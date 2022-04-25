## configuration of project crawl_vuls

# 爬取目标域名
TARGET_DOMAINS = ['www.cvedetails.com', 'git.openssl.org']
# 爬取目标URL
TARGET_URL = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=217'

DOWNLOAD_DOMAIN = 'https://git.openssl.org'

# 爬取主索引页的终止页码(0表示爬取全部页面)
PAGE_END = 1

DATASET_STORE_DIR = 'data'

CODE_FILE_STORE_DIR = DATASET_STORE_DIR + '/' + 'openssl'

VUL_LIST_FILE_NAME = 'vul_list'
