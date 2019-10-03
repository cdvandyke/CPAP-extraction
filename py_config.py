'''
This module handles config file loading and saving
'''
from os import path
import json
import tempfile
import warnings                 # For raising warnings

class settings():

    def __init__(self, location = ""):
        self.location = path
        self.values = {}

        if not path.isfile(location):
            self.default_save_location()
            warnings.warn("""The config file is not currently set up,
                        upon saving the config file will be saved at
                        {}.""".format(self.location))
        else:
            self.location = path
            self.load()

    def load(self):
        with open(self.location, 'r') as file:
            s = file.read()
            dictionary = json.loads(s)
            self.values = dictionary

    def save(self):
        with open(self.location, 'w') as file:
            json.dump(self.values, file, True)

    def default_save_location(self):
        self.location = path.join(tempfile.gettempdir(), "cpap_config.json")

    def get_values(self):
        return copy(self.values)
