'''
This module handles config file loading and saving
'''
from os import path
import json
import tempfile
import warnings                 # For raising warnings

class config(dict):

    def __init__(self, *args, **kwargs):
        self.location = ""
        self.name = ""
        super().__init__(*args, **kwargs)

    def load(self, name = "", location = ""):
        self.set_file_path(name , location)

        if not self.file_exists():
            warnings.warn("File {} not found, no configuration loaded.".format(self.fullpath()))
            return

        with open(self.location, 'r') as file:
            s = file.read()

        dictionary = json.loads(s)
        self.update(dictionary)

    def fullpath(self):
        return path.join(self.location, self.name)

    def set_file_path(self, location = "", name = ""):
        self.set_directory(location)
        self.set_filename(name)

    def set_directory(self, location):
        if path.isdir(location):
            self.location = location
        elif location == "temp":
            self.location = tempfile.gettempdir()
        else:
            self.location = path.abspath()

    def set_filename(self, name = ""):
        if name == "":
            self.name = "cpap_config.json"

        nameparts = name.split(".")
        if nameparts[-1] != "json":
            newname = ".".join(nameparts[:-1])
            self.name = "{}.{}".format(nameparts[0],"json")
            warnings.warn("""File name '{}' is not a json file,
                    file will be renamed as {}""".format(name, self.name))
        else name:
            self.name = name

    def save(self):
        try :
            with open(self.fullpath(),'w') as file:
                json.dump(self, file)
        except:
            warnings.warn("Error: Configuration not saved")
