# -*- coding: utf-8 -*-
'''
This module will take raw CPAP data as an input, and export it to JSON as an
output.

Example
-------
    $ python cpap_extraction.py 38611.000 .

Extracts the raw CPAP data from 38611.000 to a new file called
38611_extracted.JSON

Attributes
----------
SOURCE : path
    The SOURCE data file(s) to be extracted

DESTINATION : path
    The directory to place the extracted files

C_TYPES : dictionary {char: int}
    A dictionary containing the relavent number of bytes for each C Type.
    See https://docs.python.org/3/library/struct.html

VERBOSE : bool
    If True, be VERBOSE
'''
import argparse                 # For command line arguments
import os                       # For file IO
import struct                   # For unpacking binary data
from datetime import datetime   # For converting UNIX time
import warnings                 # For raising warnings
import re                       # For ripping unixtimes out of strings
import sys
if sys.version_info < (3,6):
    print("""Error Version Python version 3.6 of higher required.\n
    If you are on python 4 this is untested, as python 4 does not yet exist.""")
    exit(-1)

def setup_args():
    '''
    Sets up command-line arguments

    Attributes
    ----------
    SOURCE : path
        The SOURCE data file(s) to be extracted

    DESTINATION : path (optional)
        The directory to place the extracted files

    VERBOSE : Boolean (optional)
        If True, tell the user how long the extraction took, how big the SOURCE
        file(s) were, and how big each extracted file(s) is.

    parser : ArgumentParser
        See https://docs.python.org/2/library/argparse.html

    args : Parsed Arguments
    '''
    global SOURCE
    global DESTINATION
    global VERBOSE
    global DEBUG

    parser = argparse.ArgumentParser(description='CPAP_data_extraction')
    parser.add_argument('source', nargs=1, help='path to CPAP data')
    parser.add_argument('--destination', nargs=1, default='.',
                        help='path to place extracted files')
    parser.add_argument('-v', action='store_true', help='be VERBOSE')
    parser.add_argument('-d', action='store_true', help='debug mode')

    args = parser.parse_args()
    (SOURCE,) = args.source
    (DESTINATION,) = args.destination
    VERBOSE = args.v
    DEBUG = args.d


def open_file(source):
    '''
    Reads a SOURCE from the users' drive and returns the source as File

    Parameters
    ----------
    SOURCE : Path
        The file to be read

    Attributes
    ----------
    file : File
        The read-in file, now stored in memory

    VERBOSE : bool
        if True, print 'Reading in {SOURCE}'

    Returns
    -------
    File : The read-in file
    '''

    if VERBOSE:
        print('Reading in {}'.format(source))

    if not os.path.isfile(source):
        raise FileNotFoundError(
            'ERROR: source file {} not found!'.format(SOURCE))

    opened_file = open(source, 'rb')
    return opened_file


def read_packet(input_file, delimeter):
    '''
    Packets are sepearted using a delimeter, the .001 files, for example, use
    \xff\xff\xff\xff as their delimeter. This packet reads and returns all data
    stored in input_file up to delimeter. The data are stored with varrying
    length, some data fields are a single byte, some are 16 bytes. Because of
    this, even if we know the delimeter is four bytes, we cannot read the data
    file four bytes at a time. We must instead read one byte at a time. Once
    each byte is read in, this method checks if that byte is the first part of
    the delimeter. If it isn't, the byte is appended to packet. If it is, this
    method seeks back one byte, then checks if the next bytes match the
    delimeter, if they do, the packet is completely read, so this method
    returns. TODO: Make this explanation less terrible.

    Parameters
    ----------
    input_file : File
        A file object created by read_file(), this object contains the data
        packets to be read

    delimeter : bytes
        The 'separator' of the packets in input_file. For .001 files, the
        delimeter is b'\xff\xff\xff\xff'

    Attributes
    ----------
    packet : bytes
        The complete packet of bytes to be returned

    byte : bytes
        A single byte of data. If this byte isn't part of the delimeter, it
        gets appended to packet
    '''
    if not isinstance(delimeter, bytes):
        raise TypeError('Delimeter {} is invalid, it must be of type bytes')

    packet = b''
    if delimeter == b'':
        warnings.warn('WARNING: Delimeter is empty')
        first_byte_of_delimeter = b''
    else:
        first_byte_of_delimeter = delimeter[0].to_bytes(1, 'little')

    while True:
        byte = input_file.read(1)
        if byte == first_byte_of_delimeter:
            input_file.seek(-1, 1)
            if input_file.read(len(delimeter)) == delimeter:
                break
        elif byte == b'':
            break

        packet += byte

    return bytearray(packet)


def read_packets(input_file, delimeter):
    '''
    Using the read_packet method, returns all packet_array found in input_file
    in an array of packet_array.

    Paramters
    ---------
    input_file : File
        A file object created by read_file(), this object contains the data
        packet_array to be read

    delimeter : bytes
        The 'separator' of the packet_array in input_file. For .001 files, the
        delimeter is b'\xff\xff\xff\xff'

    Attributes
    ----------
    packet : bytes
        The packet returned by read_packet

    packet_array : Array <packets>
        The packet array to be returned
    '''
    packet_array = []
    while True:
        packet = read_packet(input_file, delimeter)
        if packet == b'':
            break
        packet_array.append(packet)

    return packet_array


def extract_packet(packet, fields):
    '''
    Extracts packets into their specified fields

    Parameters
    ----------
    packet : Bytes
        The packet, created by read_packet() to be extracted

    fields : The varying data fields that are expected to be found within
             packet

    Attributes
    ----------

    VERBOSE : bool
        if True, print 'Extracting {field} from {SOURCE}

    C_TYPES : dictionary {character: int}
        The keys of this dictionary indicate a c_type, and the values indicate
        the corresponding size of that c_type. For more info, see
        https://docs.python.org/3/library/struct.html

    data : String array
        A String array to be populated with the various fields found in the
        packet

    field : {string: character}
        Contains the name of the field (e.g., Start time, machine ID, etc.),
        and the c_type of that field (e.g., H, I, L, etc.)

    number_of_bytes : int
        The number of bytes used by the current field, determined by that
        fields' c_type

    bytes_to_be_extracted : Bytes array
        The appropriate number of Bytes, taken from packet, to be unpacked

    extracted_line : String
        The fully extracted line, ready to be appeneded to data.
        Example: Start Time: 1553245673000

    Notes
    --------
    Once the bytes from packet are correctly read and appended to data, they
    are removed from packet. This is simply to make parsing the data cleaner

    All the data are little endian, struct.unpack() expects a '<' before the
    c_type to specifiy if the Bytes are little endian, which is why a '<' is
    prepended to the c_type

    struct.unpack() returns a tuple, using (extracted_line,) = struct.unpack()
    automatically returns the unpacked tuple.
    https://stackoverflow.com/questions/13894350/what-does-the-comma-mean-in-pythons-unpack#13894363


    Returns
    -------
    data : String array
        The extracted data
    '''

    global C_TYPES
    data = {}

    for field in fields:
        if VERBOSE:
            print('Extracting {} from {}'.format(field, SOURCE))

        c_type = fields.get(field)
        number_of_bytes = C_TYPES.get(c_type)
        #remove bytes from back because little endian
        bytes_to_be_extracted = packet[:number_of_bytes]
        del packet[:number_of_bytes]

        if DEBUG:
            print('Bytes in {}: {}'.format(field, bytes_to_be_extracted))
            print('Remaining bytes in packet: {}'.format(packet))

        c_type = '<' + c_type
        # https://stackoverflow.com/questions/13894350/what-does-the-comma-mean-in-pythons-unpack#13894363
        (extracted_line,) = struct.unpack(c_type, bytes_to_be_extracted)
        data.update({field: extracted_line})

    return data


def extract_header(packet):
    '''
    Uses extract_packet to extract the header information from a packet.

    Attributes
    ----------
    fields : Dictionary {Field name: c_type}
        A dictionary containing the various fields found in a header packet,
        along with their corresponding c_type, which determines the number of
        bytes that fiels uses. See the C_TYPES dictionary.

    Returns
    --------
    A method call to extract_packet, which itself will return a string array

    Notes
    ------
    Only use this method on packets that you're sure are header packets
    '''
    global start_time

    fields = {'Magic number': 'I',
              'File version': 'H',
              'File type data': 'H',
              'Machine ID': 'I',
              'Session ID': 'I',
              'Start time': 'q',
              'End time': 'q',
              'Compression': 'H',
              'Machine type': 'H',
              'Data size': 'I',
              'CRC': 'H',
              'MCSize': 'H'}

    header = extract_packet(packet, fields)


    header["Start time"] = convert_unix_time(header["Start time"])
    header["End time"] = convert_unix_time(header["End time"])

    start_time = header["Start time"]

    return header

def data_from_packets(packets):
    data_array = []

    for packet in packets:
        length = len(packet)
        try:
            field = EXTRACTION_FIELDS[len(packet)]
            packet_data = extract_packet(packet, field)
            blank = True
            for (field, data) in packet_data.items():

                if "time" in field:
                    if data != 0:
                        blank = False
                        packet_data[field] = convert_unix_time(data)
            if blank:
                packet_data.update({"subtype": 4})
            elif length == 62:
                packet_data.update({"subtype": 0})
            elif length == 84:
                packet_data.update({"subtype": 1})
            elif length == 67:
                packet_data.update({"subtype": 1, "type":1})
            elif length == 68:
                packet_data.update({"subtype": 3})

            data_array.append(packet_data)

        except KeyError:
            break

    return data_array



def separate_int(input_string):
    '''
    REMOVE
    Converts input_string into an array, of the form [string, int, string]
    '''
    strings = re.findall(r'\D+', input_string)
    integer = re.search(r'\d+', input_string)

    separated_string = [strings[0], int(integer.group()), strings[1]]
    return separated_string


def convert_unix_time(unixtime):
    '''
    Converts an integer, unitime, to a human-readable year-month-day,
    hour-minute-second format. The raw data stores time values in milliseconds
    which is UNIX time * 1000, this method corrects for that.

    Paramters
    ---------
    unixtime : int
        The UNIX time number to be converted

    Returns
    --------
    human-readable-time : string
        The UNIX time converted to year-month-day, hour-minute-second format
    '''

    try:
        unixtime = int(unixtime / 1000)
    except TypeError:
        return 'ERROR: {} is invalid\n'.format(unixtime)

    if unixtime <= 0:
        warnings.warn('WARNING: UNIX time in {} evaluated to 0')

    if unixtime >= 2147483647:
        warnings.warn('WARNING: UNIX time in {} evaluated to beyond the year \
                       2038, if you really are from the future, hello!')

    return datetime.utcfromtimestamp(unixtime).strftime('%Y-%m-%d_%H-%M-%S')


def convert_time_string(input_string):
    '''
    REMOVE
    Takes a string of the form "Start time: 1553245673000\n" and returns the
    UNIX time converted to the more human-readable format:
    "Start time: 2019-03-22_09:07:53"
    '''
    time = separate_int(input_string)
    time[1] = convert_unix_time(time)
    converted_string = ''.join(time)
    return converted_string


def write_file(input_file, destination, packet_type=None):
    '''
    BROKEN UNTIL FURTHER NOTICE
    Writes input_file out to the users' drive, in directory destination

    Parameters
    ----------
    input_file : file
        The file to be written out

    destination : Path
        The directory to place the written out file

    packet_type : String
        The type of packet being written out (e.g., header, event summary)

    Attributes
    ----------
    SOURCE : String
        The name of the original file

    output_name : String
        The name of the output file

    VERBOSE : bool
        If True, print 'Now writing out SOURCE.JSON', where 'source' is the
        name of the orginal file.
    '''

    global start_time
    output_name = start_time + '.txt'

    # Check if input_file is empty
    if input_file == '':
        warnings.warn('WARNING: Output is empty')

    if VERBOSE:
        print('Now writting {} to file {} at {}'.format(packet_type,
                                                        output_name,
                                                        destination))

    if not os.path.isdir(destination):
        raise FileNotFoundError(
            'ERROR: destination directory {} not found!'.format(DESTINATION))

    with open(destination + '/' + output_name, 'a') as output:
        if packet_type is not None:
            output.write('---{}---\n'.format(packet_type.upper()))

        for line in input_file:
            output.write(str(line))




# Global variables
SOURCE = "."
DESTINATION = "."
VERBOSE = False
DEBUG = False
start_time = 'INVALID START TIME'
EXTRACTION_FIELDS = {
# Type 0
    62: {   'type':'B',
            'time 1': 'q',
            'time 2': 'q',
            'no entries': 'L',
            'U2': 'B',
            'double 1': 'd',
            'double 2': 'd',
            'double 3': 'd',
            'Min Val': 'd',
            'Max Val': 'd'
    },
# Type 1
    84: {    'type':'B',
            'U1': 'd',
            'U2': 'd',
            'Data type': 'L',
            'no packets': 'H',
            'time 1': 'q',
            'time 2': 'q',
            'no entries': 'L',
            'field 2': 'B',
            'double 1': 'd',
            'double 2': 'd',
            'double 3': 'd',
            'Min Val': 'd',
            'Max Val': 'd'
        },
#Type 3
    68: {   'type':'B',
            'Data type': 'L',
            'no packets': 'H',
            'time 1': 'q',
            'time 2': 'q',
            'no entries': 'L',
            'field 2': 'B',
            'double 1': 'd',
            'double 2': 'd',
            'double 3': 'd',
            'Min Val': 'd',
            'Max Val': 'd'
        },
# Header
    67: {   'Data type': 'H',
            'U1': 'H',
            'no packets': 'H',
            'time 1': 'q',
            'time 2': 'q',
            'no entries': 'L',
            'field 2': 'B',
            'double 1': 'd',
            'double 2': 'd',
            'double 3': 'd',
            'Min Val': 'd',
            'Max Val': 'd'
    }
}
# See https://docs.python.org/3/library/struct.html
C_TYPES = {'c': 1,
           'b': 1,
           'B': 1,
           'h': 2,
           'H': 2,
           'i': 4,
           'I': 4,
           'l': 4,
           'L': 4,
           'q': 8,
           'Q': 8,
           'f': 4,
           'd': 8}


if __name__ == '__main__':
    setup_args()

    DATA_FILE = open_file(SOURCE)
    PACKET_DELIMETER = b'\xff\xff\xff\xff'
    PACKETS = read_packets(DATA_FILE, PACKET_DELIMETER)
    header = extract_header(PACKETS[0])
    data = data_from_packets(PACKETS)
    with open("sample.txt",'a') as output:
        for d in data:
            output.write(str(d)+ "\n")
        for p in PACKETS:
            output.write(str(p)+"\n")

    #write_file(HEADER, DESTINATION, 'header')
