import yaml
import uuid
import os
import shutil

class Waivers:
    def __init__(self, filename: str):
        self.yaml_data = {}
        self.filename = filename
        self.swapped_filename = ""
        
        self._load_waivers()

    def _load_waivers(self):
        with open(self.filename, 'r') as yaml_file:
            try:
                self.yaml_data = yaml.safe_load(yaml_file)
            except yaml.YAMLError as exc:
                print(exc)
    
    # number of waivers held
    def size(self) -> int:
        return len(self.yaml_data['ignore'])

    # return a list of waivered IDs
    def list_ids(self) -> list:
        ids = set()
        for key in self.yaml_data['ignore']:
            ids.add(key)
        return list(ids)
    
    # remove a waiver
    def remove(self, idList: list):
        for id in idList:
            del self.yaml_data['ignore'][id.strip()]

    # update the waivers file
    def write_waivers(self, out_file_name: str = None):
        if out_file_name == None:
            out_file_name = self.filename
        with open(out_file_name, 'w') as outfile:
            yaml.dump(self.yaml_data, outfile, default_flow_style=False, sort_keys=False)





    

