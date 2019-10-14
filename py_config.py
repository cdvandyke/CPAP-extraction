'''
This module handles config file loading and saving.
It extends the base class of dict with load and save functiuonality in JSON
Note to avoid duplication all keys must be strings.
Ezra Dudden
'''
from os import path
import json
import tempfile
import warnings                 # For raising warnings

class config(dict):

    def __init__(self, *args, **kwargs):
        self.config_path = ""
        super().__init__(*args, **kwargs)

    def load(self, name = ""):
        self.set_file_path(name)

        if not path.isfile(self.config_path):
            warnings.warn("File {} not found, no configuration loaded.".format(self.config_path))
            return

        with open(self.config_path, 'r') as file:
            s = file.read()

        dictionary = json.loads(s)
        self.update(dictionary)



    def set_file_path(self, name=""):
        """
        Sets the file path to the provided path.
        The default is if no path is provided is
        TMP_PATH/py_config.json
        """
        if name == "":
            self.config_path = path.join(tempfile.gettempdir(), "py_config.json")
        else:
            if name[-5:].lower() != ".json":
                warnings.warn("File {} is not a json file.".format(name))
            self.config_path = name

        if not path.isfile(self.config_path):
            dir_path = path.dirname(self.config_path)
            if dir_path != "" and not path.isdir(dir_path):
                raise FileNotFoundError("No valid directory provided.")
            else:
                warnings.warn("The file {} does not yet exist, but will be made.".format(self.config_path))

        return str(self.config_path)

    def save(self):
        """
        Saves the file at the already provided path
        """
        try :
            with open(self.config_path,'w') as file:
                json.dump(self, file, indent=4, sort_keys=True)
        except:
            warnings.warn("Error: Configuration not saved")

"""
GLOBAL_CONFIG is for use as an importable singleton config file.
"""
GLOBAL_CONFIG = config()

if __name__ == "__main__":
    c = config()
    c.load("sample_config.json")
    print(str(c))
    c.save()
