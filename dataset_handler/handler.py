import json
import os.path
from typing import Set, List

from utils.log import *


class DatasetHandler:
    def add_to_dataset(self, CVE_id: str, vul_info: list, keywords: list,
                       vul_wfdg: List[str], vul_wfdg_no_sen: List[str], fixed_wfdg: List[str],
                       affected_vers=None, fixed_vers=None, vul_type: str = ""):
        pass

    def finish_dataset(self):
        pass

    def show_dataset(self):
        pass

    def check_dataset(self, checked_set: Set[int]) -> bool:
        pass

    def get_checked_dataset(self, *args):
        pass


class JsonDatasetHandler(DatasetHandler):
    DATASET_FILE_NAME = 'vul_data.json'
    CHECKED_DATASET_NAME = 'checked_vul.json'

    def __init__(self):
        self._json_list = []
        self._index = 0
        self._file_path = ''
        self._check_path = ''

    def set_dataset_dir(self, dataset_dir: str):
        if not os.path.exists(dataset_dir):
            try:
                os.makedirs(dataset_dir)
            except:
                perr('dataset dir: %s can not be created' % dataset_dir)
                return
        self._file_path = os.path.join(dataset_dir, self.DATASET_FILE_NAME)
        self._check_path = os.path.join(dataset_dir, self.CHECKED_DATASET_NAME)

    def add_to_dataset(self, CVE_id: str, vul_info: list, keywords: list,
                       vul_wfdg: List[str], vul_wfdg_no_sen: List[str], fixed_wfdg: List[str],
                       affected_vers=None, fixed_vers=None, vul_type: str = ""):
        if not affected_vers:
            affected_vers = []
        if not fixed_vers:
            fixed_vers = []
        json_obj = {
            'id': self._index,
            'checked': False,
            'CVE_id': CVE_id,
            'vul_info': vul_info,
            'keywords': keywords,
            'vul_wfdg': vul_wfdg,
            'vul_wfdg_no_sen': vul_wfdg_no_sen,
            'fixed_wfdg': fixed_wfdg,
            'affected_vers': affected_vers,
            'fixed_vers': fixed_vers,
            'vul_type': vul_type
        }
        self._json_list.append(json_obj)
        pinfo('append a data CVE_id:"%s" in dataset, id:%s' % (CVE_id, self._index))
        self._index += 1

    def finish_dataset(self):
        self._write_dataset(self._file_path, self._json_list)
        self._write_dataset(self._check_path, [])
        pinfo('commit all data in dataset')

    @staticmethod
    def _try_read_dataset(file_path: str):
        try:
            with open(file_path, 'r') as rf:
                return json.load(rf)
        except:
            pwarn('dataset not found, path: %s', file_path)
            return None

    @staticmethod
    def _write_dataset(file_path: str, dataset: list):
        try:
            with open(file_path, 'w') as wf:
                json.dump(dataset, wf)
        except Exception as e:
            perr(e)

    def show_dataset(self):
        json_obj = self._try_read_dataset(self._file_path)
        if not json_obj:
            return

        print(' %-3s | %-7s | %-12s | %-25s | %-30s | %-30s | %-9s | %-20s | %-60s | %-50s'
              % ('id', 'checked', 'CVE id', 'vul type', 'file paths', 'vul func', 'sensitive',
                 'keywords', 'affected versions', 'fixed versions'))
        for vul in json_obj:
            print(' %-3s  ' % vul['id'], end='')
            checked = '√' if vul['checked'] else ' '
            print(' %-7s  ' % checked, end='')
            print(' %-12s  ' % vul['CVE_id'], end='')
            print(' %-25s  ' % vul['vul_type'], end='')
            print(' %-30s  ' % vul['vul_info'][0]['file_path'], end='')
            print(' %-30s  ' % vul['vul_info'][0]['funcs'][0][0], end='')
            print(' %-9s  ' % vul['vul_info'][0]['funcs'][0][1], end='')
            print(' %-20s  ' % vul['keywords'], end='')
            print(' %-60s  ' % vul['affected_vers'], end='')
            print(' %-50s  ' % vul['fixed_vers'], end='')
            print('')

    def check_dataset(self, checked_set: Set[int]) -> bool:
        json_data = self._try_read_dataset(self._file_path)
        if not json_data:
            return False
        checked_data = []
        for idx in checked_set:
            if idx >= len(json_data):
                pwarn('"%s" is out of range in dataset' % idx)
        for i in range(len(json_data)):
            vul = json_data[i]
            if vul['id'] in checked_set:
                json_data[i]['checked'] = True
                checked_data.append(vul)
            else:
                vul['checked'] = False
        self._write_dataset(self._file_path, json_data)
        self._write_dataset(self._check_path, checked_data)
        return True

    def get_checked_dataset(self, *args):
        return self._try_read_dataset(self._check_path)


class DataHandlerFactory:
    JSON_TYPE = 'JSON'
    MYSQL_TYPE = 'MySQL'

    @classmethod
    def create_handler(cls, data_type: str):
        if data_type == cls.JSON_TYPE:
            return JsonDatasetHandler()
        return None
