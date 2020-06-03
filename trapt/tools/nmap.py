def is_scan_packet_1(conn):
    window = conn.tcp_rcv_window()
    options = conn.tcp_rcv_options()

    if window != 1:
        return False

    if len(options) != 5:
        return False

    try:
        if (options[0][0] == 'WScale' and options[0][1] == 10 and
            options[1][0] == 'NOP' and
            options[2][0] == 'MSS' and options[2][1] == 1460 and
            options[3][0] == 'Timestamp' and options[3][1][0] == 4294967295 and options[3][1][1] == 0 and
            options[4][0] == 'SAckOK' ):
              
            return True

    except IndexError:
        return False

def is_scan_packet_2(conn):
    window = conn.tcp_rcv_window()
    options = conn.tcp_rcv_options()

    if window != 63:
        return False

    if len(options) != 5:
        return False

    try:
        if (options[0][0] == 'MSS' and options[0][1] == 1400 and
            options[1][0] == 'WScale' and options[1][1] == 0 and
            options[2][0] == 'SAckOK' and
            options[3][0] == 'Timestamp' and options[3][1][0] == 4294967295 and options[3][1][1] == 0 and
            options[4][0] == 'EOL' ):
              
            return True

    except IndexError:
        return False

def is_scan_packet_3(conn):
    window = conn.tcp_rcv_window()
    options = conn.tcp_rcv_options()

    if window != 4:
        return False

    if len(options) != 6:
        return False

    try:
        if (options[0][0] == 'Timestamp' and options[0][1][0] == 4294967295 and options[0][1][1] == 0 and
            options[1][0] == 'NOP' and
            options[2][0] == 'NOP' and
            options[3][0] == 'WScale' and options[3][1] == 5 and
            options[4][0] == 'NOP' and
            options[5][0] == 'MSS' and options[5][1] == 640 ):
              
            return True

    except IndexError:
        return False

def is_scan_packet_4(conn):
    window = conn.tcp_rcv_window()
    options = conn.tcp_rcv_options()

    if window != 4:
        return False

    if len(options) != 4:
        return False

    try:
        if (options[0][0] == 'SAckOK' and
            options[1][0] == 'Timestamp' and options[1][1][0] == 4294967295 and options[1][1][1] == 0 and
            options[2][0] == 'WScale' and options[2][1] == 10 and
            options[3][0] == 'EOL' ):
              
            return True

    except IndexError:
        return False

def is_scan_packet_5(conn):
    window = conn.tcp_rcv_window()
    options = conn.tcp_rcv_options()

    if window != 16:
        return False

    if len(options) != 5:
        return False

    try:
        if (options[0][0] == 'MSS' and options[0][1] == 536 and
            options[1][0] == 'SAckOK' and
            options[2][0] == 'Timestamp' and options[2][1][0] == 4294967295 and options[2][1][1] == 0 and
            options[3][0] == 'WScale' and options[3][1] == 10 and
            options[4][0] == 'EOL' ):
              
            return True

    except IndexError:
        return False

def is_scan_packet_6(conn):
    window = conn.tcp_rcv_window()
    options = conn.tcp_rcv_options()

    if window != 512:
        return False

    if len(options) != 3:
        return False

    try:
        if (options[0][0] == 'MSS' and options[0][1] == 265 and
            options[1][0] == 'SAckOK' and
            options[2][0] == 'Timestamp' and options[2][1][0] == 4294967295 and options[2][1][1] == 0 ):
              
            return True

    except IndexError:
        return False

def is_scan_packet_t2(conn):
    if not conn.tcp_rcv_flags():
        if conn.tcp_rcv_window() == 128:
            if conn.ip_rcv_flags() == 'DF':
                return True
    return False
    
def is_scan_packet_t3(conn):
    if conn.is_tcp_rcv_flags_FPSU(): 
            if conn.tcp_rcv_window() == 256:
                if not conn.ip_rcv_flags():
                   return True
    return False

def is_scan_packet_t4(conn):
    if conn.is_tcp_rcv_flags_A(): 
            if conn.tcp_rcv_window() == 1024:
                if conn.ip_rcv_flags() == 'DF':
                    return True
    return False

def is_scan_packet_t5(conn):
    if conn.is_tcp_rcv_flags_S(): 
            if conn.tcp_rcv_window() == 31337:
                if not conn.ip_rcv_flags():
                    return True
    return False

def is_scan_packet_t6(conn):
    if conn.is_tcp_rcv_flags_A(): 
            if conn.tcp_rcv_window() == 32768:
                if conn.ip_rcv_flags() == 'DF':
                    return True
    return False

def is_scan_packet_t7(conn):
    if conn.is_tcp_rcv_flags_FPU(): 
            if conn.tcp_rcv_window() == 65535:
                if not conn.ip_rcv_flags():
                    return True
    return False

def is_scan_packet_ecn(conn):
    if conn.is_tcp_rcv_flags_SEC():
        if conn.tcp_rcv_reserved() == 4:
            if conn.tcp_rcv_urgptr() == 0xF7F5:
                if conn.tcp_rcv_window() == 3:
                    return True
    return False

def is_scan_packet_ie1(conn):
    if conn.ip_rcv_flags() == 'DF':
        if conn.ip_rcv_tos() == 0:
            if conn.icmp_rcv_type() == 8:
                if conn.icmp_rcv_code() == 9:
                    if conn.icmp_rcv_seq() == 295:
                        if conn.icmp_rcv_len() == 120:
                            return True
    return False

def is_scan_packet_ie2(conn):
    if conn.ip_rcv_tos() == 4:
        if conn.icmp_rcv_type() == 8:
            if conn.icmp_rcv_code() == 0:
                if conn.icmp_rcv_seq() == 296:
                    if conn.icmp_rcv_len() == 150:
                        return True
    return False

def is_scan_packet_u1(conn):
    if conn.ip_rcv_proto() == 17:
        if conn.ip_rcv_id() == 0x1042:
            if conn.udp_rcv_len() == 300:
                return True
    return False

def scan_options_1(conn):
    return [('MSS', 1366), 
            ('NOP', None), 
            ('WScale', 8), 
            ('SAckOK', b''), 
            ('Timestamp', (conn.tcp_snd_timestamp(), conn.tcp_rcv_timestamp()))]

def scan_options_2(conn):
    return [('MSS', 1366), 
            ('NOP', None), 
            ('WScale', 8), 
            ('SAckOK', b''), 
            ('Timestamp', (conn.tcp_snd_timestamp(), conn.tcp_rcv_timestamp()))]

def scan_options_3(conn):
    return [('MSS', 1366), 
            ('NOP', None), 
            ('WScale', 8), 
            ('NOP', None), 
            ('NOP', None), 
            ('Timestamp', (conn.tcp_snd_timestamp(), conn.tcp_rcv_timestamp()))]

def scan_options_4(conn):
    return [('MSS', 1366), 
            ('NOP', None), 
            ('WScale', 8), 
            ('SAckOK', b''), 
            ('Timestamp', (conn.tcp_snd_timestamp(), conn.tcp_rcv_timestamp()))]

def scan_options_5(conn):
    return [('MSS', 1366), 
            ('NOP', None), 
            ('WScale', 8), 
            ('SAckOK', b''), 
            ('Timestamp', (conn.tcp_snd_timestamp(), conn.tcp_rcv_timestamp()))]

def scan_options_6(conn):
    return [('MSS', 1366),
            ('SAckOK', b''), 
            ('Timestamp', (conn.tcp_snd_timestamp(), conn.tcp_rcv_timestamp()))]

def scan_options_ecn(conn):
    return [('MSS', 1366), 
            ('NOP', None), 
            ('WScale', 8), 
            ('NOP', None), 
            ('NOP', None), 
            ('SAckOK', b'')]
