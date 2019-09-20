'''
This module contains unittests for the cpap_extraction module
'''
import unittest         # For testing
import os               # For file I/O
import io               # For reading strings as files
from mock import Mock   # For mocking input and output files
from mock import patch  # For patching out file I/O
import cpap_extraction  # The module to be tested


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
        cpap_extraction.open_file('Any file')
        mocked_file.assert_called_once_with('Any file', 'rb')

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isfile', return_value=False)
    def test_open_file_does_not_exist(self, mocked_os, mocked_file):
        # Use a context manager to test raising exceptions:
        # https://docs.python.org/3.6/library/unittest.html
        with self.assertRaises(FileNotFoundError):
            cpap_extraction.open_file('Any file')


class TestReadPacket(unittest.TestCase):
    '''
    Tests the read_packet method, which takes two arguments, data_file and
    delimeter. data_file is a file, created by the read_file method, that
    contains multiple packets, each separated by delimeter. This method
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
            with a delimeter. In this scenario, a warning should be raised
        testEmptyDelimeter
            Tests whether read_file properly returns the entire packet,
            unmodified if delimeter = b''
        testInvalidDelimeter
            Tests whether read_file properly raises a ValueError if delimeter
            is not of type bytes
    '''

    def test_normal(self):
        data_file = io.BytesIO(b'\x34\x32\xff\xff\xff\xff\x42')
        delimeter = b'\xff\xff\xff\xff'
        packet = cpap_extraction.read_packet(data_file, delimeter)

        self.assertEqual(packet, b'\x34\x32')

    def test_empty(self):
        data_file = io.BytesIO(b'')
        delimeter = b'\xff\xff\xff\xff'
        packet = cpap_extraction.read_packet(data_file, delimeter)

        self.assertEqual(packet, b'')

    def test_data_file_ends_no_delimeter(self):
        data_file = io.BytesIO(b'\x34\x32')
        delimeter = b'\xff\xff\xff\xff'
        packet = cpap_extraction.read_packet(data_file, delimeter)

        self.assertEqual(packet, b'\x34\x32')

    def test_empty_delimeter(self):
        data_file = io.BytesIO(b'\x34\x32\xff\xff\xff\xff\x42')
        delimeter = b''

        with self.assertWarns(Warning):
            packet = cpap_extraction.read_packet(data_file, delimeter)
            self.assertEqual(packet, b'\x34\x32\xff\xff\xff\xff\x42')

    def test_invalid_delimeter(self):
        data_file = io.BytesIO(b'\x34\x32\xff\xff\xff\xff\x42')
        delimeter = 'test'

        with self.assertRaises(TypeError):
            packet = cpap_extraction.read_packet(data_file, delimeter)


class TestReadPackets(unittest.TestCase):
    '''
    Tests the read_packets method, which should simply call the read_packet
    method for each packet in a data file.

    Methods
    -------
        testNormal
            Tests a data_file containing two packets, separated by a
            delimeter of \xff\xff\xff\xff. Ensures that read_packets returns
            an array of size 2, and that the first index of the array contains
            the first packet, and the second index of the array contains the
            second packet

    Notes
    ------
    Other cases that may seem necessary to test, such as if the delimeter is
    invalid, the data file does not contain the delimeter, the data file is
    empty, etc. are tested in testReadPacket
    '''

    def test_nomarl(self):
        data_file = io.BytesIO(b'\x03\x0c\x01\x00\xff\xff\xff\xff\x45')
        delimeter = b'\xff\xff\xff\xff'

        packets = cpap_extraction.read_packets(data_file, delimeter)
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


class TestConvertUnixTime(unittest.TestCase):
    '''
    Tests the convert_unix_time method, which takes an int, unixtime, as an
    argument, and returns the unix time converted into year-month-day,
    hour:minute:second format. This converted format is returned as a string.

    Methods
    -------
        testNormal
            Tests a base case, 842323380000, which should evaluate to
            1996-09-10 02:43:00
        testZero
            Tests that if unixtime = 0, a warning is raised, and the returned
            string is 1970-01-01 00:00:00
        testNegative
            Tests that if unixtime < 0, a warning is raised, and the returned
            string is 1970-01-01 00:00:00
        testLargeValue
            Tests that is unixtime > 2147483647000, a warning is raised
        testNonInteger
            The CPAP machines store time in UNIX time, but in milliseconds.
            Therefore, convert_unix_time divides the passed in unixtime
            argument by 1000. Therefore, we'll want to make sure
            convert_unix_time correctly handles non-integer values, it should
            simply discard any decimal values.
        testBadArgument
            Tests that convert_unix_time correctly catches a TypeError, and
            returns 'ERROR: {unixtime} is invalid' instead.
    '''

    def test_normal(self):
        unixtime = 842323380000
        converted_time = cpap_extraction.convert_unix_time(unixtime)
        self.assertEqual(converted_time, '1996-09-10_02-43-00')

    def test_zero(self):
        unixtime = 0
        with self.assertWarns(Warning):
            converted_time = cpap_extraction.convert_unix_time(unixtime)
            self.assertEqual(converted_time, '1970-01-01_00-00-00')

    def test_negative(self):
        unixtime = -1
        with self.assertWarns(Warning):
            converted_time = cpap_extraction.convert_unix_time(unixtime)
            self.assertEqual(converted_time, '1970-01-01_00-00-00')

    def test_large_value(self):
        unixtime = 2147483647000
        with self.assertWarns(Warning):
            converted_time = cpap_extraction.convert_unix_time(unixtime)
            self.assertEqual(converted_time, '2038-01-19_03-14-07')

    def test_non_integer(self):
        # convert_unix_time should just drop extra milliseconds
        unixtime = 842323380451
        converted_time = cpap_extraction.convert_unix_time(unixtime)
        self.assertEqual(converted_time, '1996-09-10_02-43-00')

    def test_bad_argument(self):
        # convert_unix_time should catch the TypeError, when it does, it's
        # supposed to return whathever the original unixtime was
        unixtime = 'test'
        converted_time = cpap_extraction.convert_unix_time(unixtime)
        self.assertEqual(converted_time, 'ERROR: test is invalid\n')


class test_convert_time_string(unittest.TestCase):
    '''
    Tests the convert_time_string() method, which takes a string of the form
    "Start time: 1553245673000\n" and returns the UNIX time converted to the
    more human-readable format: "Start time: 2019-03-22_09:07:53"
    '''

    def test_normal(self):
        input_string = 'Start time: 1553245673000\n'
        converted_string = cpap_extraction.convert_time_string(input_string)
        self.assertEqual(converted_string, 'Start time: 2019-03-22_09-07-53\n')

class test_separate_int(unittest.TestCase):
    '''
    Tests the separate_int() method, which takes a string as an input and
    returns a tuple of the form (string, int, string)
    '''
    def test_normal(self):
        input_string = 'Test time: 0451 TEST\n'
        separated_string = cpap_extraction.separate_int(input_string)
        self.assertEqual(separated_string, ['Test time: ', 451, ' TEST\n'])


class TestWriteFile(unittest.TestCase):
    '''
    Tests the write_file method, which takes a file object created by the
    open_file method, and writes it out to a file called
    orig_file_extracted.JSON, in the specified directory on the users' drive.

    Methods
    -------
        testWriteFileDirExists
            Tests whether write_file correctly creates a file called
            orig_file_extracted.JSON in the specified directory
        testWriteFileDirDoesNotExist
            Tests whether write_file correctly raises the FileNotFoundError
            exception if the specified directory to write the file into does
            not exist
        testWriteEmptyFile
            Tests whether write_file correctly raises a warning if the input
            File is empty
    '''

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isdir', return_value=True)
    def test_write_file_dir_exists(self, mocked_os, mocked_file):
        # INVALID START TIME is the default value of start time, and thus, the
        # default name of extracted files
        cpap_extraction.write_file('Any file', 'Any directory')
        mocked_file.assert_called_once_with('Any directory/INVALID START TIME.txt',
                                            'a')

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isdir', return_value=False)
    def test_write_file_dir_does_not_exist(self, mocked_os, mocked_file):
        with self.assertRaises(FileNotFoundError):
            cpap_extraction.write_file('Any file', 'Any directory')

    @patch('cpap_extraction.open')
    @patch('cpap_extraction.os.path.isdir', return_value=True)
    def test_write_empty_file(self, mocked_os, mocked_file):
        with self.assertWarns(Warning):
            cpap_extraction.write_file('', 'Any directory')


if __name__ == '__main__':
    unittest.main()
