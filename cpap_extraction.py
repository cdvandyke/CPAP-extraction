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
import io
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
    global VERBOSE
    global DEBUG

    parser = argparse.ArgumentParser(description='CPAP_data_extraction')
    parser.add_argument('source', nargs=1, help='path to CPAP data')
    parser.add_argument('--destination', nargs=1, default='.',
                        help='path to place extracted files')
    parser.add_argument('-v', action='store_true', help='be VERBOSE')
    parser.add_argument('-d', action='store_true', help='debug mode')

    args = parser.parse_args()
    source = args.source[0]
    destination = args.destination[0]
    VERBOSE = args.v
    DEBUG = args.d

    return source, destination


def extract_file(source_file, destination = '.', verbose = False, debug = False ):
    """
    The global variable loading will need to be changed once presets and config
    files are enabled.
    """
    global VERBOSE
    global DEBUG
    VERBOSE = verbose
    DEBUG = debug

    data_file = open_file(source_file)
    packets = split_packets(data_file)
    header = extract_header(packets[0])
    packet_data = data_from_packets(packets)

    return header, packet_data


def open_file(source):
    '''
    Reads a SOURCE from the users' drive and returns the source as a
    memory copied file. This has the potential to use a lot of memmory if files
    are particularly large but as the largest file we have seen is just over
    500 KiB. This is not a pressing concern.

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
            'ERROR: source file {} not found!'.format(source))

    with open(source, 'rb') as file:
        binary_data = file.read()

    try:
        return io.BytesIO( binary_data)
    except TypeError:
        raise TypeError("ERROR: source file {} is not a binary file.".format(source))


def split_packets(input_file, delimeter = b'\xff\xff\xff\xff'):
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


def extract_header(packet):
    '''
    TODO: Test
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
            print('Extracting {} from {}'.format(field, source))

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


def data_from_packets(packets, dict_list = []):
    '''
    TODO: TEST
    Extracts the data from a packet array.
    '''
    if dict_list == []:
        dict_list = EXTRACTION_FIELDS
    data_array = []

    for packet in packets:
        length = len(packet)
        try:
            fields = field_of_length(length, dict_list)
            packet_data = extract_packet(packet, fields)
            packet_data = apply_type_and_time(length, packet_data)
            data_array.append(packet_data)

        except KeyError:
            if DEBUG:
                warnings.warn('Packet {} was not extracted'.format(packet))

    return data_array


def field_of_length(length, dict_list):
    '''
    Retrieves the dictionary of the given size
    The only expected exception sould be a KeyError
    '''
    if type(dict_list) is not type([]):
        raise TypeError("Error: the dictionary list must be a list of dictionarys.")
    elif type(dict_list[0]) is not type({}):
        raise TypeError("Error: the dictionary list must be a list of dictionarys.")
    if type(length) is not type(1):
        raise TypeError("Error: length {} is not of type Int.".format(length))

    for dict in dict_list:
        size = 0
        try:
            for (key, item) in dict.items():
                size += C_TYPES[item]
        except KeyError:
            raise ValueError("Error: Dictionary values are not valid C_TYPES" )

        if length == size:
            return dict

    # This is the only expected error
    raise KeyError("Error: No dictionary of size {} found.".format(size))


def apply_type_and_time(length, packet_data):
    """
    Applys the packet type, sub type and human readable time to the data.
    Packet data is altered regerdless but the value is returned for readability
    """
    blank = True
    for (field, data) in packet_data.items():
        if "time" in field:
            if data != 0 and type(data)is type(1):
                blank = False
                packet_data[field] = convert_unix_time(data)

    if length == 67:
        packet_data.update({'subtype': 1, 'type':1})
    elif length == 62:
        packet_data.update({'subtype': 0})
    elif length == 84:
        packet_data.update({'subtype': 1})
    elif length == 68:
        if blank:
            packet_data.update({'subtype': 4})
        else:
            packet_data.update({'subtype': 3})

    if VERBOSE:
        print("Packet type {}.{} extracted.".format(
                packet_data.get("type"), packet_data.get("subtype") ))

    return packet_data


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


# Global variables
VERBOSE = False
DEBUG = False
start_time = 'INVALID START TIME'
EXTRACTION_FIELDS = [
        # Type 0
            {   'type':'B',
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
            {   'type':'B',
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
            {   'type':'B',
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
            {   'Data type': 'H',
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
        ]

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
    source, destination = setup_args()
    header, packet_data = extract_file(source, destination, VERBOSE, DEBUG)



    #write_file(HEADER, DESTINATION, 'header')
