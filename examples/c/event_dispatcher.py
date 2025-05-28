import mmap
import os
import struct
import ctypes
import time

SHM_NAME = "/bpf_shm"
MAX_ENTRIES = 2048
SHM_SIZE = ((MAX_ENTRIES + 1) * 4096)
SHM_DATA_SIZE = SHM_SIZE - 16  # 2 size_t fields
TASK_COMM_LEN = 16

class Metrics(ctypes.Union):
    _fields_ = [
        ("latency_ns", ctypes.c_ulonglong),
        ("retval", ctypes.c_int)
    ]

class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("cmd_end_time_ns", ctypes.c_ulonglong),
        ("session_id", ctypes.c_ulonglong),
        ("mid", ctypes.c_ulonglong),
        ("smbcommand", ctypes.c_ushort),
        ("metric", Metrics),
        ("tool", ctypes.c_ubyte),
        ("is_compounded", ctypes.c_ubyte),
        ("task", ctypes.c_char * TASK_COMM_LEN)
    ]

def read_ringbuf():
    fd = os.open(f"/dev/shm{SHM_NAME}", os.O_RDWR)
    with mmap.mmap(fd, SHM_SIZE, flags= mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as m:
        while True:
            m.seek(0)
            head = struct.unpack_from("<Q", m, 0)[0]     # Read the head value
            tail = struct.unpack_from("<Q", m, 8)[0]     # Read the tail value
            print(f"[AOD] head={head}, tail={tail}")

            while tail < head:
                offset = tail % SHM_DATA_SIZE
                m.seek(16 + offset)  # Skip the head and tail fields
                raw = m.read(ctypes.sizeof(Event))
                if len(raw) < ctypes.sizeof(Event):
                    print("[AOD] Incomplete event data, skipping...")
                    break
                event = Event.from_buffer_copy(raw)
            
                print(f"[AOD] Event(pid={event.pid}, cmd_end_time_ns={event.cmd_end_time_ns}, "
                    f"session_id={event.session_id}, mid={event.mid}, smbcommand={event.smbcommand}, "
                    f"metric.latency_ns={event.metric.latency_ns}, tool={event.tool}, "
                    f"is_compounded={event.is_compounded}, task={event.task.decode(errors='ignore').strip()})")
               
                tail += ctypes.sizeof(Event)
            
            if tail != struct.unpack_from("<Q", m, 8)[0]:
                m.seek(8)
                m.write(struct.pack("<Q", tail))  # Update the tail
                m.flush()

            time.sleep(1)  # Sleep to avoid busy waiting

if __name__ == "__main__":
    read_ringbuf()
