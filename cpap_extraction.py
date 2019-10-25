# -*- coding: utf-8 -*-
'''
This module will take raw CPAP data as an input, and export it to JSON as an
output.

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
from datetime import datetime, timedelta   # For converting UNIX time
import warnings                 # For raising warnings
import re                       # For ripping unixtimes out of strings
import sys
import csv

if sys.version_info < (3,6):
    print("""Error Version Python version 3.6 of higher required.\n
    If you are on python 4 this is untested, as python 4 does not yet exist.""")
    exit(-1)

def setup_args():
    '''
    Sets up command-line arguments using a ArgumentParser
    See https://docs.python.org/2/library/argparse.html
    for details on parsing.

    Paser exits if the arguements are invalid

    Attributes
    ----------
    SOURCE : path
        The SOURCE data file(s) to be extracted

    DESTINATION : path (optional)
        The directory to place the extracted files

    VERBOSE : Boolean (optional)
        If True, tell the user how long the extraction took, how big the SOURCE
        file(s) were, and how big each extracted file(s) is.

    Returns
    -------
    :return source : path
        The binary file to be extracted

    :return destination : path
        The file path of the output file
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
    This runs the extraction algorithm as a one call function to run the whole
    module on a file.

    Parameters
    ----------
    :param source : Path
        The file to be read

    Returns
    -------
    :return header : Dict
        The binary files header data

    :return packet_data: [Array Dict]
        An array of extracted dictionaries containg packet data
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
    Reads a source from the users' drive and returns the source as a
    memory copied file. This has the potential to use a lot of memmory if files
    are particularly large but as the largest file we have seen is just over
    500 KiB. This is not a pressing concern.

    Raises Errors if the file does not exist(FileNotFoundError)
    or is not a binary file (TypeError).

    Parameters
    ----------
    :param source : Path
        The file to be read

    Returns
    -------
    File : BytesIO file
        An in memory copy of the read-in file.
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
    :param input_file : File
        A file object created by read_file(), this object contains the data
        packet_array to be read

    :param delimeter : bytes
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
        pos = input_file.tell()
        packet = read_packet(input_file, delimeter)
        if packet == b'' or len(packet) > 444:
            input_file.seek(pos)
            break
        packet_array.append(packet)

    return packet_array


def read_packet(input_file, delimeter):
    '''
    The packets are seperated but due to uneven packet length the input file
    must be read one byte at a time.

    Parameters
    ----------
    :param input_file : File
        A file object created by read_file(), this object contains the data
        packets to be read

    :param delimeter : bytes
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
    :return header: dict
        Dictionary of the binary header

    Notes
    ------
    Only use this method on packets that you're sure are header packets
    '''
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

    return header


def extract_packet(packet, fields):
    '''
    Extracts packets into their specified fields

    Parameters
    ----------
    :param packet : Bytes
        The packet, created by read_packet() to be extracted

    :param fields : The varying data fields that are expected to be found within
             packet

    Note
    ----
    struct.unpack() expects a '<' before the c_type to specifiy if the Bytes
    are little endian, which is why a '<' is prepended to the c_type

    Returns
    -------
    :return data : String array
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
    Extracts the data from a packet array.

    Parameters
    -----------
    :param packets: array of binary packets to be extracted

    :param dict_list: List of all potential extraction patterns for the packets.

    Returns
    --------
    :return data_array: [dict]
        An list of dictionarys of information extracted from the packets in the
        same order as the packets.
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
    Retrieves the dictionary of the given size for extraction.

    The only expected exception sould be a KeyError

    Parameters
    -----------
    :param length: The length of the dictionary in Bytes

    :param dict_list: List of potential Dictionary

    Returns
    --------
    :return dict: The dictionary from the dict list with corresponding length

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
    Packet data is altered regerdless but the value is returned for readability.

    Parameters
    ----------
    :param length: length to calculate packet type and subtype.

    :param packet_data: extracted packet data

    Returns
    --------
    :return packet_data: changed packet data, the return is not strictly necissary
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
    :param unixtime : int
        The UNIX time number to be converted

    Returns
    --------
    :return human-readable-time : string
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


def twos(num):
    '''
    gets the two compliment of input number
    '''
    bits = num.bit_length()
    compliment = num - (1 << bits)
    return compliment


def process_cpap_binary(packets, filehandle):
    '''
    parses file in order to determine
        -order of data/data type
        -the data
        -data start and stop times for decompressing

    Input
    ----------
    :param packets: array of dictionaries containing the following info
    :param: filehandle: rest of data

    Returns : data
    --------
    :return packets with appended inforamtion to each packet
        information appended includes data_vals and stop_times
    '''
    data = {}
    uint32_ctype = 'I'
    uint32_bytes = C_TYPES.get(uint32_ctype)
    for packet in packets:
        # check if there is associated data
        if packet["no packets"] > 0:
            ptype = packet["Data type"]
            ptypeInfo = CPAP_DATA_TYPE.get(ptype, {'stop_times':True,  'ctype':'H',  'name':"Unknown"})
            data_ctype = ptypeInfo['ctype']
            data_bytes = C_TYPES.get(data_ctype)
            data[ptype] = { }

            # Read data values
            data_vals = []
            gain = packet["double 2"]
            for _ in range(packet["no entries"]):
                read_bytes = filehandle.read(data_bytes)
                #(extracted_data,) = struct.unpack(data_ctype, read_bytes)
                extracted_data = int.from_bytes(read_bytes, byteorder='big', signed=True)
                val = round(extracted_data*gain, 3)
                if val > packet['Max Val']:
                    val = twos(int(val))
                elif val < packet['Min Val']:
                    val+=256
                data_vals.append(val)
            packet["data_vals"] = data_vals

            # Read stop times
            data_vals = []
            if ptypeInfo['stop_times']:
                for _ in range(packet["no entries"]):
                    read_bytes = filehandle.read(uint32_bytes)
                    # ignore padding byte
                    extracted_data = int.from_bytes(read_bytes[1:], byteorder='little')
                    # divide time by 1000 to get to seconds
                    data_vals.append(extracted_data/1000)
            packet["stop_times"] = data_vals
    return packets


def blankDataFill(startTime, endTime, ptype_start, interval):
    '''
    Fills in blank data for data ptype if started or ended after or before
    session start time or end time respectively

    :param startTime: start time of array -- type: datetime
    :param endTime: end time of array -- type: datetime
    :param ptype_start: when the ptype starts -- type: datetime
    :param interval: interval of times taken in seconds, e.g. 0.2 -- type float
    :return array of 2 arrays with proper number of elements according to interval
             first is stop_times, second is data_vals
    '''
    data_vals = []
    stop_times = []
    microInSec = 1000000
    for sec in range(int(((startTime - endTime).seconds - 1) / interval)):
        data_vals.append("")
        time = ptype_start + timedelta(microseconds=sec / interval * microInSec)
        stop_times.append(time.strftime('%m-%d-%y_%H:%M:%S.%f'))
    return [stop_times, data_vals]

def decompress_data(all_data, header):
    '''
    decompresses data
    :param all_data: output from process_cpap_binary
    :return raw_data: dictionary key = cpap string type, value = {'Values' : values, "Times": times
    '''
    # TODO get config file to determine desired data to be decompressed
    # ptypes to be decompressed
    desired = [4352, 4356]
    microInSec = 1000000
    raw_data = {}
    sessionStart = datetime.strptime(header['Start time'], '%Y-%m-%d_%H-%M-%S')
    # Decompress each type desired data type
    for type in desired:
        ptype_info = CPAP_DATA_TYPE.get(type, {'stop_times':True,  'ctype':'H',  'name':"Unknown"})
        ptype_data = [d for d in all_data if d['Data type'] == type][0]
        try:
            ptype_start = datetime.strptime(ptype_data['time 1'], '%Y-%m-%d_%H-%M-%S')
            ptype_end = datetime.strptime(ptype_data['time 2'], '%Y-%m-%d_%H-%M-%S')
        except:
            print("No start or end time for", type)
            continue
        decomp_data = []
        time_tags = []
        interval = ptype_info["interval"]
        intervalStep = int(interval * microInSec)

        # create stop times if none
        if not ptype_info['stop_times']:
            ptype_data['stop_times'] = [(j+1)*interval for j in range(len(ptype_data['data_vals']))]

        # match data with time tags
        counterMicroSec = 0
        for stop, val in zip(ptype_data["stop_times"], ptype_data["data_vals"]):
            intervalEnd = int(microInSec*stop)
            for i in range(counterMicroSec,intervalEnd, intervalStep):
                time = ptype_start + timedelta(microseconds=i)
                time_tags.append(time.strftime('%m-%d-%y_%H:%M:%S.%f'))
                decomp_data.append(val)
            counterMicroSec = intervalEnd

        raw_data[CPAP_DATA_TYPE[type]["name"]] = {"Times"  : time_tags,
                                                "Values" : decomp_data}
    return raw_data

##############################################################
def data_to_csv(waveform):
    try:
        with open('test.csv', 'w') as f:
            times = waveform['Times']
            vals  = waveform['Values']
            fieldnames = ['TIMES', 'VALUES']

            csv.DictWriter(f, fieldnames = fieldnames).writeheader()

            for each in range(len(times)):
                f.write("%s,%s\n"%(times[each], vals[each]))
    except IOError:
        print("CSV I/O Error")
##############################################################

# Global variables
VERBOSE = False
DEBUG = False
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
           'd': 8
           }

CPAP_DATA_TYPE = {# bool if stop times included, associated ctype for data vals, name of data
    4097 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Clear Airway Apneas event"}, # (#13 and time offset for each event)
    4098 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Obstructive Apnea"}, # (#15 and time offset for each event
    4099 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Hypopneas"}, # events per hour
    4102 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"RERA"},
    4103 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Vibratory Snore"}, # events per hour
    4104 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"System One (+DM) Vib snore event"}, # #1 and time
    4105 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Pressure Pulse"},
    4136 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Unknown"},
    4352 : {'stop_times':False, 'ctype':'h', 'interval':0.2, 'name':"Breathing Flow Rate Waveform"}, # (L/min)
    4355 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Tidal Volume"}, # (*20 for ml/min)
    4356 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Snore Volume"}, # (snores per some unit of time)
    4357 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Minute Ventilation"}, # (divide by 8 to get L)
    4358 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Respiratory Rate"}, # (BPM)
    4360 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Rate of detected mask leakage"}, # (L/min) units good
    4362 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Expiratory Time"}, # (Sec)
    4363 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Inspiratory Time"}, # (Sec)
    4364 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Unknown"},
    4366 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Unknown"},
    4374 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"AHI"},
    4375 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Total Leak Rate (L/min)"},
    4377 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Respiration Disturbance Rate"},
    4439 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Unknown"},
    4440 : {'stop_times':True,  'ctype':'H', 'interval':1.0, 'name':"Unknown"}
}


if __name__ == '__main__':
    source, destination = setup_args()
    DATA_FILE = open_file(source)
    PACKET_DELIMETER = b'\xff\xff\xff\xff'
    PACKETS = split_packets(DATA_FILE, PACKET_DELIMETER)
    header = extract_header(PACKETS[0])
    data = data_from_packets(PACKETS)
    data = process_cpap_binary(data, DATA_FILE)
    raw = decompress_data(data, header)
    data_to_csv(raw['Breathing Flow Rate Waveform'])
    exit()
