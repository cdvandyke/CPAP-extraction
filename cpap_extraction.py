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

'''
import argparse                 # For command line arguments
import os                       # For file IO
import io
import struct                   # For unpacking binary data
from datetime import datetime, timedelta # For converting UNIX time
import warnings                 # For raising warnings
import re                       # For ripping unixtimes out of strings
import sys
import csv
from py_config import CONFIG


if sys.version_info < (3,6):
    print("""Error Version Python version 3.6 of higher required.\n
    If you are on python 4 this is untested, as python 4 does not yet exist.""")
    exit(-1)


class files:
    '''
    A class with comparison overload so sorting can be done using pythons
    built in sort. Also has a gap method to find the time between the end of
    one file and the start of another.

    '''
    def __init__(self, name, header):
        self.name = name
        self.start_time = header['Start time']
        self.end_time = header['End time']

    def __lt__(self, other):
        '''
        This lets me call sort on a list of them
        '''
        return self.start_time < other.start_time

    def gap_time(self, other):
        """"
        Time in hours between end of one file and the beginning of the next
        """
        time = other.start_time - self.end_time
        return time.days*24.0 + time.seconds/3600.0

    def elapsed_time(self, other):
        """
        Time in hours between the start of the file and the end of the given files.

        Parameters
        ----------
        :param other : files
            The file to be read

        Returns
        -------
        :return source : float
        Time difference in hours
        """
        time = other.end_time - self.start_time
        return time.days*24.0 + time.seconds/3600.0

    def __str__(self):
        return str(self.name)


def setup_args():
    '''
    Sets up command-line arguments using a ArgumentParser
    See https://docs.python.org/2/library/argparse.html
    for details on parsing.

    Paser exits if the arguements are invalid

    Returns
    -------
    :return source : path
        The binary file to be extracted

    :return destination : path
        The file path of the output file
    '''
    source = ""
    parser = argparse.ArgumentParser(description='CPAP_data_extraction')
    parser.add_argument('file', nargs=1, help='path to 001 file or config file')
    parser.add_argument('--destination', nargs=1, default='.',
                        help='path to place extracted files')
    parser.add_argument('-v', action='store_true', help='be verbose')
    parser.add_argument('-d', action='store_true', help='debug mode')

    args = parser.parse_args()
    file = args.file[0]

    if file[-5:].lower() == ".json":
        CONFIG.load(file)
        source = CONFIG["Load Path"]
        destination = CONFIG["Save Path"]

    else:
        source = file
        destination = args.destination[0]
        CONFIG.setdefault("As Directory", False)

    CONFIG.setdefault("Verbose", args.v)
    CONFIG.setdefault("Debug", args.d)

    if CONFIG["As Directory"] != os.path.isdir(source) :
        raise FileNotFoundError("No directory provided.")

    if not CONFIG["As Directory"] and source[-4:] !=".001":
        raise FileNotFoundError("No valid .001 file found")

    return source, destination

def process_groups(source, destination):
    """
    """
    groups = file_sort(source)
    groups = filter(groups)
    for group in groups:
        group_header = {}
        raws = {}
        for file in group:
            try:
                data_file = open_file(file.name)
                if CONFIG["Verbose"]:
                    print("Processing file {}.".format(file.name))
                header = extract_header(data_file)
                #Use the header for the first packet of a group
                if group_header == {}:
                    group_header = header
                packets = split_packets(data_file)
                packet_data = data_from_packets(packets)
                data = process_cpap_binary(packet_data, data_file)
                raw = decompress_data(data)
                raws = merge_raws(raws, raw)
            except Error as e:
                print("Error processing file {}, file skipped".format(file.name))
                print(e)

        if raws:
            data_to_csv(raws, destination, group_header)


def merge_raws(raws, raw):
    """
    Takes two raws and merges them.

    """
    if not raw:
        return raws
    if not raws:
        return raw

    for item in raw:
        if item in raws:
            for value in raw[item]:
                if value in raws[item]:
                    raws[item][value] = raws[item][value] + raw[item][value]
                else:
                    raws[item].update({value: raw[item][value]})
        else:
            raws.update({item: raw[item]})
    return raws

def filter(file_list):

    class file_group:
        """
        This class is just a collection to keep all the values associated together
        some things are calculated here but no internal values should be changed after the fact.
        """
        def __init__(self, files):
            self.files = files
            offset = timedelta(hours = 20)
            offset_start = files[0].start_time - offset
            self.day_str = offset_start.strftime(CONFIG["Date Format"])
            self.duration = files[0].elapsed_time(files[-1])

    if "ALL" in CONFIG["Dates"]:
        in_date_range = lambda x: True
    else:
        valid_dates = dates_for_match(CONFIG["Dates"])
        in_date_range = lambda x: x in valid_dates

    files_by_day = {}
    for group in file_list:
        fg = file_group(group)
        day = fg.day_str
        if in_date_range(day):
            if day in files_by_day:
                if fg.duration > files[day].duration:
                    files_by_day[day] = fg
            else:
                files_by_day.update({day: fg})

    valid_groups = [v.files for k,v in files_by_day.items()]
    return valid_groups


def dates_for_match(dates):
    """
    Finds all the days as required by the dates

    Parameters
    ----------
    :param dates: [String]
        array of strings, the strings can be '<DATE> TO <DATE>' or '<DATE>'
        where <DATE> is determined by CONFIG["Date Format"]

    Returns
    -------
    :return valid_dates: [String]
        An array of strings with all the valid dates.
    """

    valid_dates = []
    if "ALL" in dates:
        raise ValueError("ALL and dates specified in date range")
    for v in dates:
        if "TO" in v:
            date_range = expand_date_range(v)
            valid_dates = valid_dates + date_range
        else:
            #Pack and unpack to fix formatting issues
            day =  datetime.strptime(v, CONFIG["Date Format"])
            valid_dates.append(day.strftime(CONFIG["Date Format"]))
    return valid_dates


def expand_date_range(s_range):
    """
    Expands the range out for a date range.

    Parameters
    ----------
    :param s_range: String
        string of the form '<DATE> TO <DATE>'
        where <DATE> is determined by CONFIG["Date Format"]

    Returns
    -------
    :return grouped: [[files]]
        An array of arrays of files, each sub array is a group of files from
        the same day.
    """
    range = []
    vals = s_range.split(" TO ")
    if len(vals) != 2:
        raise ValueError("Improper value in date range")

    start =  datetime.strptime(vals[0], CONFIG["Date Format"])
    end =   datetime.strptime(vals[-1], CONFIG["Date Format"])

    while start <= end:
        range.append(start.strftime(CONFIG["Date Format"]))
        start = start + timedelta(days=1)

    return range


def file_sort(source):
    """
    This creates a list of files from the source path and then turns it into a
    sorted and grouped list of files(obj).

    Parameters
    ----------
    :param source : Path
        The folder of files to be read

    Returns
    -------
    :return groups: [[files]]
        An array of arrays of files, each sub array is a group of files from
        the same day.
    """
    list = []
    for dir, sub, f in os.walk(source):
        for file in f:
            name = os.path.join(source,file)
            if name[-4:] == ".001":
                header = extract_header(open_file(name))
                list.append(files(name, header))
    list.sort()
    groups = group(list)
    return groups


def group(list):
    """
    This groups a list of files objects into groups

    Parameters
    ----------
    :param list : [files]
        A sorted list of files.

    Returns
    -------
    :return grouped: [[files]]
        An array of arrays of files, each sub array is a group of files from
        the same day.
    """
    prev = list[0]
    grouped = [[prev]]

    for file in list[1:]:
        gap = prev.gap_time(file)
        if gap < float(CONFIG["Awake Period"]):
            grouped[-1].append(file)
        else:
            grouped.append([file])
        prev = file

    return grouped

def extract_file(source_file, destination = '.', configfile ="" ):
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

    if CONFIG["Verbose"]:
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


def split_packets(input_file, delimiter = b'\xff\xff\xff\xff'):
    '''
    Using the read_packet method, returns all packet_array found in input_file
    in an array of packet_array.
    TODO: the packet spliting needs to take into account if there is more than
    one packet of a type, the "no packets" has some information of how many packets of a type there are but this needs some interpertings
    Paramters
    ---------
    :param input_file : File
        A file object created by read_file(), this object contains the data
        packet_array to be read

    delimiter : bytes
        The 'separator' of the packet_array in input_file. For .001 files, the
        delimiter is b'\xff\xff\xff\xff'

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
        packet = read_packet(input_file, delimiter)
        if packet == b'' or len(packet) > 444:
            input_file.seek(pos)
            break
        packet_array.append(packet)

    return packet_array


def read_packet(input_file, delimiter):
    '''
    The packets are seperated but due to uneven packet length the input file
    must be read one byte at a time.

    Parameters
    ----------
    :param input_file : File
        A file object created by read_file(), this object contains the data
        packets to be read

    delimiter : bytes
        The 'separator' of the packets in input_file. For .001 files, the
        delimiter is b'\xff\xff\xff\xff'

    Attributes
    ----------
    packet : bytes
        The complete packet of bytes to be returned

    byte : bytes
        A single byte of data. If this byte isn't part of the delimiter, it
        gets appended to packet
    '''
    if not isinstance(delimiter, bytes):
        raise TypeError('Delimeter {} is invalid, it must be of type bytes')

    packet = b''
    if delimiter == b'':
        raise ValueError("Deliminator is empty")
    else:
        first_byte_of_delimiter = delimiter[0].to_bytes(1, 'little')

    while True:
        byte = input_file.read(1)
        if byte == first_byte_of_delimiter:
            input_file.seek(-1, 1)
            if input_file.read(len(delimiter)) == delimiter:
                break
        elif byte == b'':
            break

        packet += byte

    return bytearray(packet)


def extract_header(input_file):
    '''
    TODO: Test
    Uses extract_packet to extract the header information from a packet.

    Attributes
    ----------
    fields : Dictionary {Field name: c_type}
        A dictionary containing the various fields found in a header packet,
        along with their corresponding c_type, which determines the numberDudden of
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
              'Number of Packets': 'H'}

    header = {}
    for k,v in fields.items():
        byte_size = C_TYPES[v]
        byte = input_file.read(byte_size)
        format  = "<" + v
        data_value = struct.unpack(format , byte)[0]
        if CONFIG["Verbose"]:
            print("Pair added to header {}: {}".format(k, data_value))
        header.update({k: data_value})

    header["Start time"] = datetime.utcfromtimestamp(header["Start time"]/1000)
    header["End time"] = datetime.utcfromtimestamp(header["End time"]/1000)
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
        if CONFIG["Verbose"]:
            print('Extracting {} from {}'.format(field, source))

        c_type = fields.get(field)
        number_of_bytes = C_TYPES.get(c_type)
        #remove bytes from back because little endian
        bytes_to_be_extracted = packet[:number_of_bytes]
        del packet[:number_of_bytes]

        if CONFIG["Debug"]:
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
            if CONFIG["Debug"]:
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
            if data <= 0 and type(data)is type(1):
                blank = False
                packet_data[field] = datetime.utcfromtimestamp(data/1000)

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

    if CONFIG["Verbose"]:
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
        pass
    except TypeError:
        return 'ERROR: {} is invalid\n'.format(unixtime)

    if unixtime <= 0:
        warnings.warn('WARNING: UNIX time in {} evaluated to 0')

    if unixtime >= 2147483647:
        warnings.warn('WARNING: UNIX time in {} evaluated to beyond the year \
                       2038, if you really are from the future, hello!')

    return datetime.utcfromtimestamp(unixtime).strftime(CONFIG["Date Format"])


def twos(num):
    '''
    gets the two compliment of input number

    Args:
     num: signed decimal number

    Returns:
     compliment: twos compliment of num
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

    Args:
     packets: array of dictionaries containing the following info
     filehandle: rest of data

    Returns :
    --------
    packets: packets from input with appended information to each packet.
        Information appended includes data_vals and stop_times
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

def decompress_data(all_data):
    '''
    Decompresses data from the binary .001 file

    Args:
     all_data: output from process_cpap_binary

    Returns:
     raw_data: dictionary key = cpap string type, value = {'Values' : values, "Times": times}
    '''
    # TODO get config file to determine desired data to be decompressed
    # ptypes to be decompressed
    desired = [int(x) for x in CONFIG["Data Types"]]
    microInSec = 1000000
    raw_data = {}
    # Decompress each type desired data type
    for type in desired:
        ptype_info = CPAP_DATA_TYPE.get(type, {'stop_times':True,  'ctype':'H',  'name':"Unknown"})
        ptype_data = [d for d in all_data if d['Data type'] == type][0]
        try:
            ptype_start = datetime.utcfromtimestamp(ptype_data['time 1']/1000)
            ptype_end = datetime.utcfromtimestamp(ptype_data['time 2']/1000)
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
                time_tags = time_tags + [time.strftime(CONFIG["Date Format"] + '_%H:%M:%S.%f')]
                decomp_data.append(val)
            counterMicroSec = intervalEnd

        raw_data[CPAP_DATA_TYPE[type]["name"]] = {"Times"  : time_tags,
                                                "Values" : decomp_data}
    return raw_data



def data_to_csv(rawData, destination, header):
    '''
        Converts data from dictionary into csv file with the following format for columns:
        Date, Time, Value
        --Each data type will be in a unique file

        Args:
         rawData: dictionary key = cpap string type, value = {'Values' : values, "Times": times }
        '''
    for title, data in rawData.items():
        date_str = header["Start time"].strftime(CONFIG["Date Format"])
        filename = "{}:{}.csv".format(date_str, title)
        filepath = os.path.join(destination, filename)
        with open(filepath, "w", newline="") as dataFile:
            dataWriter = csv.writer(dataFile)
            dataWriter.writerow(["DATE", "TIME", "VALUE"])
            for time, val in zip(data["Times"], data["Values"]):
                (date, time) = time.split("_")
                dataWriter.writerow([date, time, val])

# Global variables
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
    if CONFIG.get("As Directory", False):
        process_groups(source, destination)
    else:
        data_file = open_file(source)
        delimiter = b'\xff\xff\xff\xff'
        header = extract_header(data_file)
        packets = split_packets(data_file, delimiter)
        packet_data = data_from_packets(packets)
        data = process_cpap_binary(packet_data, data_file)
        raw = decompress_data(data)
        data_to_csv(raw, destination, header)
