'''
This module contains unittests for the py_config module
'''
import unittest         # For testing
import os               # For file I/O
import io               # For reading strings as files
import tempfile         # For locating the temp directory.
from mock import Mock   # For mocking input and output files
from mock import patch  # For patching out file I/O
import py_config   # The module to be tested

class TestLoad(unittest.TestCase):
    '''
    Tests the open method, which reads in a file and updates the dictionary
    accordingly
    '''

    @patch('py_config.open')
    @patch('py_config.path.isfile', return_value=True)
    @patch('py_config.json.loads', return_value={})
    def test_open_file_exists(self, mock_json, mocked_os, mocked_file):
        test_config = py_config.config()
        test_config.load('Any file')
        mocked_file.assert_called_once_with('Any file', 'r')

    @patch('py_config.open')
    @patch('py_config.path.isfile', return_value=False)
    def test_open_file_does_not_exist(self, mocked_os, mocked_file):
        test_config = py_config.config()
        with self.assertRaises(FileNotFoundError):
            test_config.load("invalid/somepath")


class TestSetFilePath(unittest.TestCase):
    def test_default_value(self):
        test_config = py_config.config()
        test_config.set_file_path()
        expected = os.path.join(tempfile.gettempdir(), "py_config.json")
        self.assertEqual(expected, test_config.config_path)

    def test_local_config(self):
        test_config = py_config.config()
        with self.assertWarns(Warning):
            test_config.set_file_path("THISCONFIG.JSON")
        self.assertEqual("THISCONFIG.JSON", test_config.config_path)

    def test_wrong_filetype(self):
        test_config = py_config.config()
        with self.assertWarns(Warning):
            test_config.set_file_path("NotAJson.txt")
        self.assertEqual("NotAJson.txt", test_config.config_path)

class TestSaveFile(unittest.TestCase):
    def setup(self):
        test_config = py_config.config()
        test_config.update({"this":"that"})
        return test_config

    @patch('py_config.open', create=True)
    def test_save_successful(self, mock_file):
        test_config = self.setup()
        test_config.save()
        mock_file.assert_called_once_with(test_config.config_path, 'w')

    @patch('py_config.open', side_effect = Exception('Boom!'))
    def test_save_unsuccessful(self, mock_file):
        test_config = self.setup()
        with self.assertWarns(Warning):
            test_config.save()

class TestDefaults(unittest.TestCase):
    def test_contents(self):
        test_config = py_config.config()
        self.assertFalse("Debug" in test_config)
        self.assertFalse(test_config["Debug"])
        self.assertTrue("Debug" in test_config)


if __name__ == '__main__':
    unittest.main()
