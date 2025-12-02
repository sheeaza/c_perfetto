import argparse
import re
from enum import Enum
from protos.perfetto.trace import trace_pb2
from google.protobuf import text_format
import os

trace_data_lut = {
        'head': 'Event, Time, Cycle',
        'type': {
            'proc': { 'create': 'Create Process Name' },
            'thread': { 'create': 'Create Thread',
                       'name': 'Thread Name'},
            'userevent555': 'User Event 555',
            'func_enter': 'Function Enter',
            'func_exit': 'Function Eexit',
            },
        'class': {
            'user': 'User',
            'kcall': 'Kernel Calls'
            },
        'data': {
            'async': 'Async_',
            'end': 'Event End',
            }
}

def to_timestamp(ts: str):
    us_match = re.search(r'(\d+)us', ts)
    if us_match:
        us = int(us_match.group(1))
    else:
        us = 0

    ms_match = re.search(r'(\d+)ms', ts)
    if ms_match:
        ms = int(ms_match.group(1))
    else:
        ms = 0

    s_match = re.search(r'(\d+)s', ts)
    if s_match:
        s = int(s_match.group(1))
    else:
        s = 0
    return us * 1000 + ms * 1000000 + s * 1000000000

def data_get_pid(data: str):
    return int(re.search(r'\bpid:(\d+)', data).group(1))

def data_get_tid(data: str):
    return int(re.search(r'\btid:(\d+)', data).group(1))

def owner_get_proc_name(data: str):
    return re.search(r'(\S+)\W+(\S+)', data).group(1)

def owner_get_thread_name(data: str):
    return re.search(r'(\S+)\W+(\S+)', data).group(2)

def data_get_thread_name(data: str):
    return int(re.search(r'\bname:(\S+)', data).group(1))

def data_get_string(data: str):
    return re.search(r'\bstring:(.+)', data).group(1)

def data_get_string_without_d(data: str):
    return re.search(r'\bstring:(.+?)\W*d\d+:', data).group(1)

def data_get_func_src_file(data: str):
    return re.search(r'\bsrcfile:(\S+)', data).group(1)

def data_get_func_addr(data: str):
    return re.search(r'\bfunction_addr:(\S+)', data).group(1)

def log_to_struct_dict(in_log_path):
    with open(in_log_path, 'r') as fp:
        # find data type line
        found = False
        type_line = []
        for line in fp:
            if trace_data_lut['head'] in line:
                _line = line.strip().split(', ')
                type_line = _line
                found = True
                break

        if not found:
            raise ValueError(f'cannot found data type line in {in_log_path}')

        # handle trace data line by line
        trace_data = []
        for line in fp:
            if len(line.strip()) == 0:
                continue

            line_val = line.strip().split(', ', len(type_line) - 1)
            if len(line_val) != len(type_line) and len(line_val) != (len(type_line) - 1): # data optional
                raise ValueError(f'miss match count line: {line}\n{line_val}\nexpected format is {type_line}')
            trace = { k: v for(k, v) in zip(type_line, line_val) }
            trace_data.append(trace)
    
    return trace_data

def log_to_proto(in_log_path, out_proto_path):
    trace_data = log_to_struct_dict(in_log_path)

    uuid = [0]
    def get_uuid(x = uuid):
        y = x[0]
        x[0] = x[0] + 1
        return y
    trusted_id = [0]
    def get_trust_id(x = trusted_id):
        y = x[0]
        x[0] = x[0] + 1
        return y

    # handle formatted trace data
    pb_trace = trace_pb2.Trace()
    trace_table = {}
    #  xxx
    # todo: dup thread name, process name
    #  xxx
    xxx = [ x for x in trace_data if 'xxxrver' in x['Owner'] ]
    for trace in xxxerver_trace:
        if trace['Type'] == trace_data_lut['type']['proc']['create']:
            packet = pb_trace.packet.add()
            packet.track_descriptor.uuid = get_uuid()
            packet.track_descriptor.process.pid = data_get_pid(trace['Data'])
            packet.track_descriptor.process.process_name = trace['Owner']

            # store to table
            proc = {}
            proc['pid'] = packet.track_descriptor.process.pid
            proc['uuid'] = packet.track_descriptor.uuid
            trace_table[trace['Owner']] = proc
            continue

        if trace['Type'] == trace_data_lut['type']['thread']['create']:
            packet = pb_trace.packet.add()
            packet.track_descriptor.uuid = get_uuid()
            packet.track_descriptor.parent_uuid = trace_table[owner_get_proc_name(trace['Owner'])]['uuid']
            packet.track_descriptor.thread.pid = data_get_pid(trace['Data'])
            packet.track_descriptor.thread.tid = data_get_tid(trace['Data'])
            packet.track_descriptor.thread.thread_name = owner_get_thread_name(trace['Owner'])

            # store to table
            proc = {}
            proc['uuid'] = packet.track_descriptor.uuid
            proc['trust_id'] = get_trust_id()
            trace_table[packet.track_descriptor.thread.thread_name] = proc
            continue

        if trace['Type'] == trace_data_lut['type']['userevent555']:
            packet = pb_trace.packet.add()
            packet.timestamp = to_timestamp(trace['Time'])
            event_type = packet.track_event.TYPE_SLICE_BEGIN
            if trace_data_lut['data']['end'] in trace['Data']:
                event_type = packet.track_event.TYPE_SLICE_END
            packet.track_event.type = event_type
            packet.track_event.track_uuid = trace_table[owner_get_thread_name(trace['Owner'])]['uuid']
            packet.track_event.name = data_get_string_without_d(trace['Data'])
            packet.trusted_packet_sequence_id = trace_table[owner_get_thread_name(trace['Owner'])]['trust_id']
            continue

    with open(out_proto_path, 'wb') as fp:
        fp.write(pb_trace.SerializeToString())
    with open(out_proto_path + 'str', 'w') as fp:
        fp.write(text_format.MessageToString(pb_trace))

def qnx_func_to_proto(in_log, symbol, offset):
    trace_data = log_to_struct_dict(in_log_path)

    uuid = [0]
    def get_uuid(x = uuid):
        y = x[0]
        x[0] = x[0] + 1
        return y
    trusted_id = [0]
    def get_trust_id(x = trusted_id):
        y = x[0]
        x[0] = x[0] + 1
        return y

    # handle formatted trace data
    pb_trace = trace_pb2.Trace()
    trace_table = {}
    # todo: dup thread name, process name
    for trace in trace_data:
        if trace['Type'] == trace_data_lut['type']['proc']['create']:
            packet = pb_trace.packet.add()
            packet.track_descriptor.uuid = get_uuid()
            packet.track_descriptor.process.pid = data_get_pid(trace['Data'])
            packet.track_descriptor.process.process_name = trace['Owner']

            # store to table
            proc = {}
            proc['pid'] = packet.track_descriptor.process.pid
            proc['uuid'] = packet.track_descriptor.uuid
            trace_table[trace['Owner']] = proc
            continue

        if trace['Type'] == trace_data_lut['type']['thread']['create']:
            packet = pb_trace.packet.add()
            packet.track_descriptor.uuid = get_uuid()
            packet.track_descriptor.parent_uuid = trace_table[owner_get_proc_name(trace['Owner'])]['uuid']
            packet.track_descriptor.thread.pid = data_get_pid(trace['Data'])
            packet.track_descriptor.thread.tid = data_get_tid(trace['Data'])
            packet.track_descriptor.thread.thread_name = owner_get_thread_name(trace['Owner'])

            # store to table
            proc = {}
            proc['uuid'] = packet.track_descriptor.uuid
            proc['trust_id'] = get_trust_id()
            trace_table[packet.track_descriptor.thread.thread_name] = proc
            continue

        if trace['Type'] == trace_data_lut['type']['func_enter']:
            packet = pb_trace.packet.add()
            packet.timestamp = to_timestamp(trace['Time'])
            packet.track_event.type = packet.track_event.TYPE_SLICE_BEGIN
            packet.track_event.track_uuid = trace_table[owner_get_thread_name(trace['Owner'])]['uuid']
            packet.track_event.name = data_get_func_src_file(trace['Data']) + data_get_func_addr(trace['Data'])
            packet.trusted_packet_sequence_id = trace_table[owner_get_thread_name(trace['Owner'])]['trust_id']
            continue

        if trace['Type'] == trace_data_lut['type']['func_exit']:
            packet = pb_trace.packet.add()
            packet.timestamp = to_timestamp(trace['Time'])
            packet.track_event.type = packet.track_event.TYPE_SLICE_END
            packet.track_event.track_uuid = trace_table[owner_get_thread_name(trace['Owner'])]['uuid']
            packet.track_event.name = data_get_func_src_file(trace['Data']) + data_get_func_addr(trace['Data'])
            packet.trusted_packet_sequence_id = trace_table[owner_get_thread_name(trace['Owner'])]['trust_id']
            continue

    with open(out_proto_path, 'wb') as fp:
        fp.write(pb_trace.SerializeToString())
    with open(out_proto_path + 'str', 'w') as fp:
        fp.write(text_format.MessageToString(pb_trace))

from ctypes import *
class traceevent(Structure):
	_fields_ = [
            ("event", c_uint32, 10),
            ("event_c", c_uint32, 5),
            ("nop", c_uint32, 9),
            ("cpu", c_uint32, 6),
            ("struct", c_uint32, 2),
            ("data", c_uint32 * 3),
            ]
_TRACE_EMPTY_C           =  (0x00000000u<<10)
_TRACE_CONTROL_C         =  (0x00000001u<<10)
_TRACE_KER_CALL_C        =  (0x00000002u<<10)
_TRACE_INT_C             =  (0x00000003u<<10)
_TRACE_PR_TH_C           =  (0x00000004u<<10)
_TRACE_SYSTEM_C          =  (0x00000005u<<10)
_TRACE_CONTAINER_C       =  _TRACE_SYSTEM_C		//Container class never defined
_TRACE_USER_C            =  (0x00000006u<<10)
_TRACE_COMM_C            =  (0x00000007u<<10)
_TRACE_QUIP_C            =  (0x00000008u<<10)
_TRACE_SEC_C             =  (0x00000009u<<10)
_TRACE_QVM_C             =  (0x0000000au<<10)
_TRACE_TOT_CLASS_NUM     =  (11)

enum {
	_NTO_TRACE_EMPTY,
	_NTO_TRACE_CONTROL,
	_NTO_TRACE_KERCALL,
	_NTO_TRACE_KERCALLENTER,
	_NTO_TRACE_KERCALLEXIT,
	_NTO_TRACE_KERCALLINT,
	_NTO_TRACE_INT,
	_NTO_TRACE_INTENTER,
	_NTO_TRACE_INTEXIT,
	_NTO_TRACE_PROCESS,
	_NTO_TRACE_THREAD,
	_NTO_TRACE_VTHREAD,
	_NTO_TRACE_USER,
	_NTO_TRACE_SYSTEM,
	_NTO_TRACE_COMM,
	_NTO_TRACE_INT_HANDLER_ENTER,
	_NTO_TRACE_INT_HANDLER_EXIT,
	_NTO_TRACE_QUIP,
	_NTO_TRACE_SEC,
    _NTO_TRACE_QVM,
    _NTO_TRACE_NUM_CLASSES
};
def kev_internal_to_external(event_c, event):
    if event_c == _TRACE_COMM_C:
        return kk
    pass

def kev_parse_ev(ev):
    ext_event_c, ext_event = kev_internal_to_external(ev.event_c, ev.event)
    pass

def kev2txt(kev, txt):
    kev_size = os.path.getsize(kev)
    cnt = kev_size // sizeof(traceevent)
    trace_evs_t = [traceevent] * cnt
    with open(kev, 'rb') as f:
        trace_evs = (traceevent * cnt)()
        f.readinto(trace_evs)

    for ev in trace_evs:
        kev_parse_ev(ev)

def main():
    parser = argparse.ArgumentParser(prog='PROG')

    sub_parsers = parser.add_subparsers(dest='cmd')

    parser_proto = sub_parsers.add_parser('to_proto')
    parser_proto.add_argument('out_pro', help='path to output proto file')
    parser_proto.add_argument('in_log', help='path to input log file')

    parser_qnx_func_proto = sub_parsers.add_parser('qnx_func_trace_to_proto')
    parser_qnx_func_proto.add_argument('out_pro', help='path to output proto file')
    parser_qnx_func_proto.add_argument('in_log', help='path to input log file')
    parser_qnx_func_proto.add_argument('symbol', help='path to input elf symbol file')
    parser_qnx_func_proto.add_argument('--offset', help='load offset symbol, default to 0x100c0000', default=0x100c0000)

    parser_kev2txt = sub_parsers.add_parser('kev2txt')
    parser_kev2txt.add_argument('out', help='path to output txt file')
    parser_kev2txt.add_argument('input', help='path to input kev file')

    args = parser.parse_args()

    if args.cmd == 'to_proto':
        return log_to_proto(args.in_log, args.out_pro)
    elif args.cmd == 'qnx_func_trace_to_proto':
        return qnx_func_to_proto(args.in_log, args.symbol, args.offset)
    elif args.cmd == 'kev2txt':
        return kev2txt(args.input, args.out)
    else:
        raise E

if __name__ == '__main__':
    main()
