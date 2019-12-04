'''
This module contains unittests for the cpap_extraction module
'''
import unittest         # For testing
import os               # For file I/O
import io               # For reading strings as files
from mock import Mock   # For mocking input and output files
from mock import patch  # For patching out file I/O
import cpap_extraction  # The module to be tested
import py_config
from datetime import datetime

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
            cpap_extraction.open_file('Any file')
        mocked_file.assert_called_once_with('Any file', 'rb')

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isfile', return_value=False)
    def test_open_file_does_not_exist(self, mocked_os, mocked_file):
        # Use a context manager to test raising exceptions:
        # https://docs.python.org/3.6/library/unittest.html
        with self.assertRaises(FileNotFoundError):
            cpap_extraction.open_file('Any file')


class TestSetupArgs(unittest.TestCase):
    def test_normal(self):
        cpap_extraction.sys.argv = [ "cpap_extraction.py", "inputfile.001"]
        input, output_path = cpap_extraction.setup_args()
        self.assertEqual(input, "inputfile.001")
        self.assertEqual(output_path, ".")

    def test_bad_argument(self):
        """
        This test puts extra stuff in the output
        """
        if False:
            cpap_extraction.sys.argv = [ "cpap_extraction.py", "inputfile", "extrastuff"]
            with self.assertRaises(SystemExit):
                cpap_extraction.setup_args()

    def test_flags(self):
        cpap_extraction.CONFIG = py_config.config()
        cpap_extraction.sys.argv = [ "cpap_extraction.py", "-v", "-d", "inputfile.001", "--destination=output"]
        input, output_path = cpap_extraction.setup_args()
        self.assertEqual(input, "inputfile.001")
        self.assertEqual(output_path, "output")
        self.assertTrue(cpap_extraction.CONFIG["Verbose"])
        self.assertTrue(cpap_extraction.CONFIG["Debug"])


class TestReadPacket(unittest.TestCase):
    '''
    Tests the read_packet method, which takes two arguments, data_file and
    delimiter. data_file is a file, created by the read_file method, that
    contains multiple packets, each separated by delimiter. This method
    returns the first complete packet it finds within data file, or it returns
    nothing if no packet is found. read_packet leaves the seak point of
    data_file at the beginning of the next packet.

    These tests use Python's io class:
    https://docs.python.org/3/library/io.html

    Methods
    -------
        testNormal
            Tests whether read_file performs as expected in a base case
        testEmpty
            Tests that read_file properly returns an empty BytesArray if
            data_file is empty
        testDataFileEndsNoDelimeter
            Tests whether read_file properly returns a packet that did not end
            with a delimiter. In this scenario, a warning should be raised
        testEmptyDelimeter
            Tests whether read_file properly returns the entire packet,
            unmodified if delimiter = b''
        testInvalidDelimeter
            Tests whether read_file properly raises a ValueError if delimiter
            is not of type bytes
    '''

    def test_normal(self):
        data_file = io.BytesIO(b'\x34\x32\xff\xff\xff\xff\x42')
        delimiter = b'\xff\xff\xff\xff'
        packet = cpap_extraction.read_packet(data_file, delimiter)

        self.assertEqual(packet, b'\x34\x32')

    def test_empty(self):
        data_file = io.BytesIO(b'')
        delimiter = b'\xff\xff\xff\xff'
        packet = cpap_extraction.read_packet(data_file, delimiter)

        self.assertEqual(packet, b'')

    def test_data_file_ends_no_delimiter(self):
        data_file = io.BytesIO(b'\x34\x32')
        delimiter = b'\xff\xff\xff\xff'
        packet = cpap_extraction.read_packet(data_file, delimiter)

        self.assertEqual(packet, b'\x34\x32')

    def test_empty_delimiter(self):
        data_file = io.BytesIO(b'\x34\x32\xff\xff\xff\xff\x42')
        delimiter = b''

        with self.assertRaises(ValueError):
            packet = cpap_extraction.read_packet(data_file, delimiter)

    def test_invalid_delimiter(self):
        data_file = io.BytesIO(b'\x34\x32\xff\xff\xff\xff\x42')
        delimiter = 'test'

        with self.assertRaises(TypeError):
            packet = cpap_extraction.read_packet(data_file, delimiter)


class TestSplitPackets(unittest.TestCase):
    '''
    Tests the split_packets method, which should simply call the split_packet
    method for each packet in a data file.

    Methods
    -------
        testNormal
            Tests a data_file containing two packets, separated by a
            delimiter of \xff\xff\xff\xff. Ensures that split_packets returns
            an array of size 2, and that the first index of the array contains
            the first packet, and the second index of the array contains the
            second packet

    Notes
    ------
    Other cases that may seem necessary to test, such as if the delimiter is
    invalid, the data file does not contain the delimiter, the data file is
    empty, etc. are tested in testReadPacket
    '''

    def test_normal(self):
        data_file = io.BytesIO(b'\x03\x0c\x01\x00\xff\xff\xff\xff\x45')
        delimiter = b'\xff\xff\xff\xff'

        packets = cpap_extraction.split_packets(data_file, delimiter)
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0], b'\x03\x0c\x01\x00')
        self.assertEqual(packets[1], b'\x45')


class TestExtractPacket(unittest.TestCase):
    '''
    Tests the extract_packet method, which takes two arguments, a packet of
    bytes, and a dictionary {field name: c_type}, where field name is the name
    of the packet's various fields, and c_type is the field's corresponding
    c_type, which determines how many bytes that field should be.
    '''

    def test_normal(self):
        fields = {'Test unsigned short': 'H',
                  'Test unsigned int': 'I',
                  'Test unsigned long': 'L',
                  'Test unsigned long long': 'Q'}

        input_file = bytearray(b'''\x2a\x00\xc3\x01\x00\x00\xc9\x07\xcc\x00\xaa\xaa\x42\x1a\xcd\x79\x40\x09''')

        correct_output = {'Test unsigned short': 42,
                          'Test unsigned int': 451,
                          'Test unsigned long': 13371337,
                          'Test unsigned long long': 666666666666666666}

        extracted_packet = cpap_extraction.extract_packet(input_file, fields)

        self.assertEqual(extracted_packet, correct_output)


class TestDataFromPackets(unittest.TestCase):
    def test_standard(self):
        packets = [bytearray(b'\x2a\x00\xc3\x01\x00\x00\xc9\x07\xcc\x00\xaa\xaa\x42\x1a\xcd\x79\x40\x09'),
                   bytearray(b'\x2a\x00\xc3\x01\x00\x00\xc9\x07\xcc\x00'),
                   bytearray(b'\x2a\x00\xc3\x01\x00\x00\xc9\x07\xcc\x00\xaa\xaa\x42\x1a')
        ]
        fields = [{'Test unsigned short': 'H',
                  'Test unsigned int': 'I',
                  'Test unsigned long': 'L',
                  'Test unsigned long long': 'Q'},
                  {'Test unsigned short': 'H',
                    'Test unsigned int': 'I',
                    'Test unsigned long': 'L'}]
        correct_output = [{'Test unsigned short': 42,
                              'Test unsigned int': 451,
                              'Test unsigned long': 13371337,
                              'Test unsigned long long': 666666666666666666
                        },
                        {   'Test unsigned short': 42,
                            'Test unsigned int': 451,
                            'Test unsigned long': 13371337,
                        }]

        output = cpap_extraction.data_from_packets(packets, fields)
        self.assertEqual(output, correct_output)


class TestApplyDateandTime(unittest.TestCase):
    """
        This tests applying the date and time to a dictionary.
        As well as correctly addressing the packet type
    """
    def test_type_0_3(self):
        expected_output = {'type': 0, 'time 1': datetime.utcfromtimestamp(1551428926), 'time 2': datetime.utcfromtimestamp(1551441255), 'no entries': 207, 'field 2': 1, 'subtype': 3}
        input = {'type': 0, 'time 1': 1551428926000, 'time 2': 1551441255000, 'no entries': 207, 'field 2': 1}
        output = cpap_extraction.apply_type_and_time(68, input)
        self.assertEqual(output, expected_output)

    def test_first_packet(self):
        input = {'Data type': 4440, 'U1': 0, 'no packets': 1}
        expected_output = {'Data type': 4440, 'U1': 0, 'no packets': 1, 'type':1, 'subtype':1}
        output = cpap_extraction.apply_type_and_time(67, input)
        self.assertEqual(output, expected_output)

    def test_type_0_4(self):
        expected_output = {'type': 0, 'Data type': 4377, 'no packets': 1, 'time 1': datetime.utcfromtimestamp(1551428926), 'time 2': datetime.utcfromtimestamp(1551428926), 'subtype': 4}
        input = {'type': 0, 'Data type': 4377, 'no packets': 1, 'time 1': 1551428926000, 'time 2': 1551428926000}
        output = cpap_extraction.apply_type_and_time(68, input)
        self.assertEqual(output, expected_output)

    def test_type_1(self):
        expected_output = {'type': 1, 'Data type': 4377, 'no packets': 1, 'time 1': datetime.utcfromtimestamp(1), 'time 2': datetime.utcfromtimestamp(2), 'subtype': 1}
        input = {'type': 1, 'Data type': 4377, 'no packets': 1, 'time 1': 1000, 'time 2': 2000}
        output = cpap_extraction.apply_type_and_time(84, input)
        self.assertEqual(output, expected_output)

    def test_type_0_0(self):
        expected_output = {'type': 0, 'Data type': 4377, 'no packets': 1, 'time 1': 0, 'time 2': 0, 'no entries': 207, 'field 2': 1, 'subtype': 0 }
        input = {'type': 0, 'Data type': 4377, 'no packets': 1, 'time 1': 0, 'time 2': 0, 'no entries': 207, 'field 2': 1}
        output = cpap_extraction.apply_type_and_time(62, input)
        self.assertEqual(output, expected_output)

    def test_no_change(self):
        input = {'type': 1, 'Data type': 4377, 'no packets': 1, 'time 1': 0, 'time 2': 0, 'no entries': 207, 'field 2': 1}
        inputf = input.copy()
        output = cpap_extraction.apply_type_and_time(-1, inputf)
        self.assertDictEqual(output, input)


class TestFieldOfLength(unittest.TestCase):
    '''
    Tests the "fields_of_length" method
    '''
    def test_type_error(self):
        with self.assertRaises(TypeError):
            cpap_extraction.field_of_length(25, {'Just a dictionary not a list': 'e'})
        with self.assertRaises(TypeError):
            cpap_extraction.field_of_length("nope", [{'somedata': 'Q'}])
        with self.assertRaises(TypeError):
            cpap_extraction.field_of_length(25, ['Not a dictioary'])

    def test_key_error(self):
        with self.assertRaises(KeyError):
            cpap_extraction.field_of_length(25, [{"only 8": 'Q'}])

    def test_value_error(self):
        with self.assertRaises(ValueError):
            cpap_extraction.field_of_length(25, [{"invalid c type": 'nope'}])

    def test_normal(self):
        eight = {"8": 'q'}
        four = {"4": 'i'}
        sixteen = {"8": 'q', "another 8": 'Q'}
        dicts = [eight, four, sixteen]
        self.assertEqual(cpap_extraction.field_of_length(4,dicts), four)


class TestExtractionSystem(unittest.TestCase):
    """
        This is designed a wholistic system test.
    """
    def read_results_file(self, filename):
        results = []
        with open(filename, 'r') as rfile:
            text = rfile.read()
            lines = text.split('\n')
            for line in lines:
                expected = line.strip()
                if expected != "":
                    if expected[0] != '#':
                        results.append(expected)
        return results


    def test_file_one(self):
        results = self.read_results_file("TestFiles/test_one_result.txt")
        header, packet_data = cpap_extraction.extract_file("TestFiles/test_one.001")

        header = cpap_extraction.extract_header(data_file)
        headerstr = str(header).strip()
        self.assertEqual(headerstr, results.pop(0))

        for packet in packet_data:
            self.assertEqual(str(packet).strip(), results.pop(0))

        self.assertTrue(len(results) == 0)

class TestCSVExport(unittest.TestCase):
    """
        Tests the CSV export method
    """

    def test_type_error(self):
        data = {
            "1": "0",
            "2": "0",
            "3": "2",
            "4": "5",
            "5": "5",
            "6": "2",
        }
        Times = [1,2,3,4,5,6]

        header = {"Start time": datetime.utcfromtimestamp(1551428926)}
        with self.assertRaises(TypeError):
            cpap_extraction.data_to_csv(data, ".", header)

    def test_missing_value(self):
        Times = ["1_1","2_2","3_3","4_4","5_5","6_6"]
        Values = [0,0,2,5,5]
        data = {"Test": {"Times" : Times, "Values" : Values}}
        header = {"Start time": datetime.utcfromtimestamp(1551428926)}
        with self.assertRaises(TypeError):
            cpap_extraction.data_to_csv(data, ".", header)


if __name__ == '__main__':
    unittest.main()
