"""This class is responsible for writing bpf programs and attaching them to right hooks"""
# pylint: disable=unused-argument
import os 
import json
import shutil
from sync import registrar, Manager
from collections import OrderedDict

class BpfManager(Manager):    
    """
    Comments on class 
    """
    bpf_filename = "/etc/config/bpf"

    def initialize(self):
        """Initialize this module"""
        registrar.register_settings_file("settings", self)
        registrar.register_file(self.bpf_filename, "bpfgen", self)

    #def sanitize_settings(self, settings_file):
    #    """
    #    Perform santiization on settings meant to be written back.
    #    """
    #    pass

    #def validate_settings(self, settings_file):
    #    """
    #    Perform validation of settings
    #    """
    #    pass

    def create_settings(self, settings_file, prefix, delete_list, filepath):
        """creates settings"""
        print("%s: Initializing settings" % self.__class__.__name__)

    def sync_settings(self, settings_file, prefix, delete_list):
        """syncs settings"""
        print ("%s: Syncing settings" % self.__class__.__name__)
        self.write_bpf_file(settings_file.settings, prefix)

    def write_bpf_file(self, settings, prefix=""):
        """writes prefix/etc/config/bpf"""
        filename = prefix + self.bpf_filename
        file_dir = os.path.dirname(filename)
        if not os.path.exists(file_dir):
            os.makedirs(file_dir)
        
        filter_rules = settings['firewall']['tables']['filter']['chains'][0]['rules']

        file = open(filename, "w+")
        file.write("\n")

        json_str=''
        for rule in filter_rules:
            if rule['action']['type'] == "DROP" \
               and rule.get('enabled') == True \
               and len(rule.get('conditions')) == 1:
                for condition in rule.get('conditions'):                
                    if condition.get('type') == "SERVER_ADDRESS":
                        json_str = json.dumps(rule, indent=4)
                        file.write(json_str)
                        file.write("\n")
                    else:
                        break

        

        file.flush()
        file.close()

        print("%s: Wrote %s" % (self.__class__.__name__, filename))


registrar.register_manager(BpfManager())
