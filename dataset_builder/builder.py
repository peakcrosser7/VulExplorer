import json
import os.path


class DatasetBuilder:
    def add_to_dataset(self, CVE_id: str, file_paths: list,
                       vul_func: str, sensitive_line: int, keywords: list,
                       vul_wfdg, vul_wfdg_no_sen, fixed_wfdg,
                       affected_vers=None, fixed_vers=None, vul_type: str = ""):
        pass


class JsonDatasetBuilder(DatasetBuilder):
    def __init__(self):
        self._file_path = './'
        self._json_list = []

    def set_file_path(self, dir_path: str, file_name: str):
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        if not file_name.endswith('.json'):
            file_name += '.json'
        self._file_path = os.path.join(dir_path, file_name)

    def add_to_dataset(self, CVE_id: str, file_paths: list,
                       vul_func: str, sensitive_line: int, keywords: list,
                       vul_wfdg, vul_wfdg_no_sen, fixed_wfdg,
                       affected_vers=None, fixed_vers=None, vul_type: str = ""):
        if not affected_vers:
            affected_vers = []
        if not fixed_vers:
            fixed_vers = []
        json_obj = {
            'CVE_id': CVE_id,
            'file_paths': file_paths,
            'vul_func': vul_func,
            'sensitive_line': sensitive_line,
            'keywords': keywords,
            'vul_wfdg': vul_wfdg,
            'vul_wfdg_no_sen': vul_wfdg_no_sen,
            'fixed_wfdg': fixed_wfdg,
            'affected_vers': affected_vers,
            'fixed_vers': fixed_vers,
            'vul_type': vul_type
        }
        self._json_list.append(json_obj)

    def __del__(self):
        with open(self._file_path, 'w') as wf:
            json.dump(self._json_list, wf)


class DataBuilderFactory:
    JSON_TYPE = 'JSON'
    MYSQL_TYPE = 'MySQL'

    @classmethod
    def create_builder(cls, data_type: str):
        if data_type == cls.JSON_TYPE:
            return JsonDatasetBuilder()
        return None
