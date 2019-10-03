'''
This module contains unittests for the cpap_extraction module
'''
import unittest         # For testing
import os               # For file I/O
import io               # For reading strings as files
from mock import Mock   # For mocking input and output files
from mock import patch  # For patching out file I/O
import py_config   # The module to be tested


class TestOpenFile(unittest.TestCase):
    '''
    Tests the open_file method, which reads in a binary file, and returns it
    as a file object.

    Methods
    -------
        testReadFileExists
            Tests whether open_file correctly opens a file that exists
        testReadFileDoesNotExist
            Tests whether open_file correctly raises the FileNotFoundError
            exception if the specified file does not exist
    '''

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isfile', return_value=True)
    def test_open_file_exists(self, mocked_os, mocked_file):
        with self.assertRaises(TypeError):
            py_config.settings("somepath")
        mocked_file.assert_called_once_with('Any file', 'r')

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isfile', return_value=False)
    def test_open_file_does_not_exist(self, mocked_os, mocked_file):
        # Use a context manager to test raising exceptions:
        # https://docs.python.org/3.6/library/unittest.html
        with self.assertRaises(FileNotFoundError):
            cpap_extraction.open_file('Any file')
