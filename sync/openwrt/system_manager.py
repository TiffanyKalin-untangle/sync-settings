import os
import stat
import sys
import subprocess
import datetime
import traceback
from sync import registrar

# This class is responsible for writing FIXME
# based on the settings object passed from sync-settings
class SystemManager:
    def initialize(self):
        pass

    def preprocess_settings(self, settings):
        pass

    def validate_settings(self, settings):
        pass
    
    def create_settings(self, settings, prefix, delete_list, filename):
        print("%s: Initializing settings" % self.__class__.__name__)
        settings['system'] = {}
        settings['system']['hostName'] = 'mfw'
        settings['system']['domainName'] = 'example.com'
        
    def sync_settings(self, settings, prefix, delete_list):
        pass
        
registrar.register_manager(SystemManager())
