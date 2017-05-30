# Copyright 2013 Alexander Craig
# Copyright 2012 James McCauley
# Copyright 2008 (C) Nicira, Inc.
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.

#======================================================================
#
#                          IGMP v1/v2
#
#                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Ver * | Type  | MRT/Unused ** | Checksum                      |
#   +-------+-------+---------------+-------------------------------+
#   | Group Address                                                 |
#   +-------------------------------+-------------------------------+
#
#   *  In v2, there is no Version field, and Type is the whole 8 bits
#   ** Max Response Time in v2 only
#
#======================================================================
#
#                   IGMP v3 - Membership Query Message
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Type = 0x11  | Max Resp Code |           Checksum            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                         Group Address                         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address [1]                      |
#   +-                                                             -+
#   |                       Source Address [2]                      |
#   +-                              .                              -+
#   .                               .                               .
#   .                               .                               .
#   +-                                                             -+
#   |                       Source Address [N]                      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================
#
#                IGMP v3 - Membership Report Message
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Type = 0x22  |    Reserved   |           Checksum            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Reserved            |  Number of Group Records (M)  |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   .                                                               .
#   .                        Group Record [1]                       .
#   .                                                               .
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   .                                                               .
#   .                        Group Record [2]                       .
#   .                                                               .
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                               .                               |
#   .                               .                               .
#   |                               .                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   .                                                               .
#   .                        Group Record [M]                       .
#   .                                                               .
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================
#
#                        IGMP v3 - Group Record
#
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Multicast Address                       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address [1]                      |
#   +-                                                             -+
#   |                       Source Address [2]                      |
#   +-                                                             -+
#   .                               .                               .
#   .                               .                               .
#   .                               .                               .
#   +-                                                             -+
#   |                       Source Address [N]                      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   .                                                               .
#   .                         Auxiliary Data                        .
#   .                                                               .
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import struct
from packet_utils import *
from packet_base import packet_base
from pox.lib.addresses import *

# Type flags used in IGMP headers
MEMBERSHIP_QUERY     = 0x11
MEMBERSHIP_REPORT_V1 = 0x12
MEMBERSHIP_REPORT_V2 = 0x16
MEMBERSHIP_REPORT_V3 = 0x22
LEAVE_GROUP_V2       = 0x17

# Additional types derived from type flag in header + additional data
UNPARSED_IGMP_PACKET = 0
MEMBERSHIP_QUERY_V1  = 1
MEMBERSHIP_QUERY_V2  = 2
MEMBERSHIP_QUERY_V3  = 3

# IGMP v3 Group Record types
MODE_IS_INCLUDE         = 1
MODE_IS_EXCLUDE         = 2
CHANGE_TO_INCLUDE_MODE  = 3
CHANGE_TO_EXCLUDE_MODE  = 4
ALLOW_NEW_SOURCES       = 5
BLOCK_OLD_SOURCES       = 6

# IGMP multicast address
IGMP_ADDRESS = IPAddr("224.0.0.22")
IGMP_V3_ALL_SYSTEMS_ADDRESS = IPAddr("224.0.0.1")

# IGMP IP protocol
IGMP_PROTOCOL = 2

class igmpv3_group_record:
    GROUP_RECORD_HEADER_LEN = 8

    MODE_IS_INCLUDE         = MODE_IS_INCLUDE
    MODE_IS_EXCLUDE         = MODE_IS_EXCLUDE
    CHANGE_TO_INCLUDE_MODE  = CHANGE_TO_INCLUDE_MODE
    CHANGE_TO_EXCLUDE_MODE  = CHANGE_TO_EXCLUDE_MODE
    ALLOW_NEW_SOURCES       = ALLOW_NEW_SOURCES
    BLOCK_OLD_SOURCES       = BLOCK_OLD_SOURCES

    def __init__(self):
        self.record_type = 0
        self.aux_data_len = 0
        self.num_sources = 0
        self.multicast_address = None
        self.source_addresses = []
        self.aux_data = None   # Defined but not used in IGMPv3
        
        self.len = 0
        
    def get_addr_set(self):
        return set(self.source_addresses)
    
    def parse(self, raw):
        '''Parses a byte array into a single IGMPv3 group record. Returns the number of bytes processed.'''
        assert isinstance(raw, bytes)
        self.record_type, self.aux_data_len, self.num_sources, ip = \
            struct.unpack('!BBHi', raw[:self.GROUP_RECORD_HEADER_LEN])
        self.multicast_address = IPAddr(ip, networkOrder = False)
        # print 'Read group record: Type: %d, aux_data_len: %d, num_sources: %d' % (self.record_type, self.aux_data_len, self.num_sources)
        # print 'Read group record multicast address: %s' % (self.multicast_address)
        for i in range(0, self.num_sources):
            (source_address,) = struct.unpack("!i", raw[self.GROUP_RECORD_HEADER_LEN + (i * 4):self.GROUP_RECORD_HEADER_LEN + ((i + 1) * 4)])
            # print 'Read group record source address: %s' % (source_address)
            self.source_addresses.append(IPAddr(source_address, networkOrder=False))
        self.len = self.GROUP_RECORD_HEADER_LEN + (self.num_sources * 4)
        return self.len
    
    def pack(self):
        s = struct.pack('!BBHi', self.record_type, self.aux_data_len, self.num_sources, self.multicast_address.toSigned(networkOrder=False))
        for i in range(0, self.num_sources):
                s += struct.pack("!i", self.source_addresses[i].toSigned(networkOrder=False))
        # TODO - This implementation relies on the aux_data field being empty, and may not work with future IGMP extensions
        # if(self.aux_data_len != 0):
            # log.error('Auxiliary data specified with group record, but not included in packed version.')
        return s


class igmpv3 (packet_base):
    """
    IGMP Message
    """

    MIN_LEN = 8
    TYPE_FIELD_LEN = 1
    V3_QUERY_HDR_LEN = 12
    V3_REPORT_HDR_LEN = 8

    IGMP_ADDRESS = IGMP_ADDRESS
    IGMP_PROTOCOL = IGMP_PROTOCOL

    UNPARSED_IGMP_PACKET = UNPARSED_IGMP_PACKET
    MEMBERSHIP_QUERY     = MEMBERSHIP_QUERY
    MEMBERSHIP_QUERY_V1  = MEMBERSHIP_QUERY_V1
    MEMBERSHIP_QUERY_V2  = MEMBERSHIP_QUERY_V2
    MEMBERSHIP_QUERY_V3  = MEMBERSHIP_QUERY_V3
    MEMBERSHIP_REPORT_V1 = MEMBERSHIP_REPORT_V1
    MEMBERSHIP_REPORT_V2 = MEMBERSHIP_REPORT_V2
    MEMBERSHIP_REPORT_V3 = MEMBERSHIP_REPORT_V3
    LEAVE_GROUP_V2       = LEAVE_GROUP_V2

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.dlen = 0
        self.ver_and_type = 0
        self.msg_type = UNPARSED_IGMP_PACKET
        self.max_response_time = 0
        self.suppress_router_processing = False
        self.qrv = 0
        self.qqic = 0
        self.csum = 0
        self.address = IPAddr("0.0.0.0")
        self.num_sources = 0
        self.source_addresses = []
        self.num_group_records =0
        self.group_records = []
        self.extra = b''

        if raw is not None:
          self.parse(raw)

        self._init(kw)

#    TODO - Needs to account for different message types / IGMP versions. The header functionality is currently
#    included in the parse function
#    def hdr (self, payload):
#        s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time, \
#                        0, self.address.toSigned(networkOrder=False))
#        s += self.extra
#        self.csum = checksum(s)
#        s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time,  \
#                        self.csum, self.address.toSigned(networkOrder=False))
#        s += self.extra
#        return s

    def parse (self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        self.dlen = len(raw)
        if self.dlen < self.MIN_LEN:
            self.msg('packet data too short to parse')
            return None

        # Read type field
        (self.ver_and_type,) = struct.unpack("!B", raw[:self.TYPE_FIELD_LEN])
        if self.ver_and_type == self.MEMBERSHIP_REPORT_V3:
            # Read v3 Membership Report specific fields
            self.msg_type = self.MEMBERSHIP_REPORT_V3
            self.csum, self.num_group_records = struct.unpack("!xHxxH", raw[self.TYPE_FIELD_LEN:self.V3_REPORT_HDR_LEN])
            
            group_records_processed_bytes = 0
            for i in range(0, self.num_group_records):
                group_record = igmpv3_group_record()
                group_records_processed_bytes += group_record.parse(raw[self.V3_REPORT_HDR_LEN + group_records_processed_bytes:])
                self.group_records.append(group_record)
                # print 'Processed %d bytes of group records.' % group_records_processed_bytes
                
            self.extra = raw[self.V3_REPORT_HDR_LEN + group_records_processed_bytes:]
            
        else:
            # Read fields shared between all IGMP message versions other than v3 Membership Reports
            self.max_response_time, self.csum, ip = \
                struct.unpack("!BHi", raw[self.TYPE_FIELD_LEN:self.MIN_LEN])
            self.address = IPAddr(ip, networkOrder = False)
            if self.max_response_time >= 128 :
                # TODO - Handle floating point max_response_time
                self.err('IGMP packet parsed with floating point max_response_time - CURRENTLY UNSUPPORTED')
            
            if self.ver_and_type == MEMBERSHIP_QUERY and self.dlen == 8 and self.max_response_time == 0:
                # v1 Membership Query
                self.msg_type = MEMBERSHIP_QUERY_V1
                self.extra = raw[self.MIN_LEN:]
                
            elif self.ver_and_type == MEMBERSHIP_QUERY and self.dlen == 8 and self.max_response_time != 0:
                # v2 Membership Query
                self.msg_type = MEMBERSHIP_QUERY_V2
                self.extra = raw[self.MIN_LEN:]
                
            elif self.ver_and_type == MEMBERSHIP_QUERY and self.dlen >= 12:
                # v3 Membership Query
                self.msg_type = MEMBERSHIP_QUERY_V3
                s_flag_qrv_byte = 0
                s_flag_qrv_byte, self.qqic, self.num_sources, = \
                    struct.unpack("!BBH", raw[self.MIN_LEN:self.V3_QUERY_HDR_LEN])
                if self.qqic >= 128 :
                    #TODO - Handle floating point qqic
                    self.err('IGMP packet parsed with floating point qqic - CURRENTLY UNSUPPORTED')
                self.suppress_router_processing = True if s_flag_qrv_byte & 0x08 else False
                self.qrv = s_flag_qrv_byte & 0x07
                for i in range(0, self.num_sources):
                    (source_address, ) = struct.unpack("!i", raw[self.V3_QUERY_HDR_LEN + (i * 4):self.V3_QUERY_HDR_LEN + ((i + 1) * 4)])
                    self.source_addresses.append(source_address.toSigned(networkOrder=False))
                self.extra = raw[self.V3_QUERY_HDR_LEN + (self.num_sources * 4):]
                    
            else:
                # Other message type
                self.msg_type = self.ver_and_type
                self.extra = raw[self.MIN_LEN:]

        s = self.pack(False)
        csum = checksum(s)
        if csum != self.csum:
            self.err("IGMP checksums don't match")
        else:
            self.parsed = True
    
    def pack(self, recalc_checksum = True):
        if recalc_checksum:
            packed_no_checksum = self.pack(False)
            self.csum = checksum(packed_no_checksum)
        
        if self.max_response_time >= 128 :
            # TODO - Handle floating point max_response_time
            self.err('IGMP packet packed with floating point max_response_time - CURRENTLY UNSUPPORTED')
        if self.qqic >= 128 :
            #TODO - Handle floating point qqic
            self.err('IGMP packet packed with floating point qqic - CURRENTLY UNSUPPORTED')
        
        s = None
        if self.ver_and_type == self.MEMBERSHIP_REPORT_V3:
            if recalc_checksum:
                s = struct.pack("!BxHxxH", self.ver_and_type, self.csum, self.num_group_records)
            else:
                s = struct.pack("!BxHxxH", self.ver_and_type, 0, self.num_group_records)
            for i in range(0, self.num_group_records):
                s += self.group_records[i].pack()            
        else:
            if recalc_checksum:
                s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time, \
                        self.csum, self.address.toSigned(networkOrder=False))
            else:
                s = struct.pack("!BBHi", self.ver_and_type, self.max_response_time, \
                        0, self.address.toSigned(networkOrder=False))
            
            if self.ver_and_type == MEMBERSHIP_QUERY and self.dlen >= 12:
                # v3 Membership Query
                s_flag_qrv_byte = self.qrv
                if(self.suppress_router_processing):
                    s_flag_qrv_byte = s_flag_qrv_byte | 0x07
                s += struct.pack("!BBI", s_flag_qrv_byte, self.qqic, self.num_sources)
                for i in range(0, self.num_sources):
                    s += struct.pack("!i", self.source_addresses[i].toSigned(networkOrder=False))
                    
        s += self.extra
        return s

    def get_msg_type(self):
        '''Returns an integer identifier which indicates both the type and IGMP version of the message.
        
        Note that for MEMBERSHIP QUERY message types, this value will not be equal to the type and version
        passed in the message header (as this does not uniquely identify the version), and the constants
        defined in this class must be used for comparisons. The output of this call is only valid after
        a call to parse.
        '''
        return self.msg_type

    def __str__ (self):
        type_string = 'Unknown type - vt:%02x' % (self.ver_and_type)
        if self.msg_type == MEMBERSHIP_QUERY_V1:
            type_string = 'v1 Membership Query'
        elif self.msg_type == MEMBERSHIP_QUERY_V2:
            type_string = 'v2 Membership Query'
        elif self.msg_type == MEMBERSHIP_QUERY_V3:
            type_string = 'v3 Membership Query'
        elif self.msg_type == MEMBERSHIP_REPORT_V1:
            type_string = 'v1 Membership Report'
        elif self.msg_type == MEMBERSHIP_REPORT_V2:
            type_string = 'v2 Membership Report'
        elif self.msg_type == MEMBERSHIP_REPORT_V3:
            type_string = 'v3 Membership Report'
            group_record_index = 0
            for group_record in self.group_records:
                if group_record.record_type == MODE_IS_INCLUDE:
                    type_string += ' | ' + str(group_record_index) + ':' \
                            + str(group_record.multicast_address) + ':MODE_IS_INCLUDE'
                elif group_record.record_type == MODE_IS_EXCLUDE:
                    type_string += ' | ' + str(group_record_index) + ':' \
                            + str(group_record.multicast_address) + ':MODE_IS_EXCLUDE'
                elif group_record.record_type == CHANGE_TO_INCLUDE_MODE:
                    type_string += ' | ' + str(group_record_index) + ':' \
                            + str(group_record.multicast_address) + ':CHANGE_TO_INCLUDE_MODE'
                    if group_record.num_sources == 0:
                        type_string += ' (Equiv V2 LEAVE GROUP)'
                elif group_record.record_type == CHANGE_TO_EXCLUDE_MODE:
                    type_string += ' | ' + str(group_record_index) + ':' \
                            + str(group_record.multicast_address) + ':CHANGE_TO_EXCLUDE_MODE'
                elif group_record.record_type == ALLOW_NEW_SOURCES:
                    type_string += ' | ' + str(group_record_index) + ':' \
                            + str(group_record.multicast_address) + ':ALLOW_NEW_SOURCES'
                elif group_record.record_type == BLOCK_OLD_SOURCES:
                    type_string += ' | ' + str(group_record_index) + ':' \
                            + str(group_record.multicast_address) + ':BLOCK_OLD_SOURCES'
                group_record_index += 1
        elif self.msg_type == LEAVE_GROUP_V2:
            type_string = 'v2 Leave Group'
            
        s = "[IGMP | "
        s += "%s | %s" % (type_string, self.address)
        return s + "]"
