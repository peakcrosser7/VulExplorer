## configuration of project crawl_vuls

# 爬取目标域名
TARGET_DOMAINS = ['www.cvedetails.com', 'git.openssl.org']
# 爬取目标URL
# OpenSSL所有漏洞
# TARGET_URL = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=217'
# OpenSSL-1.0.1a漏洞
TARGET_URL = 'https://www.cvedetails.com/vulnerability-list/vendor_id-217/' \
             'product_id-383/version_id-465603/Openssl-Openssl-1.0.1a.html'

DOWNLOAD_DOMAIN = 'https://git.openssl.org'

PAGE_START = 1

PAGE_END = 2

DATASET_STORE_DIR = 'data'

CODE_FILE_STORE_DIR = DATASET_STORE_DIR + '/' + 'openssl-1.0.1a'

VUL_LIST_FILE_NAME = 'vul_list_101a'
