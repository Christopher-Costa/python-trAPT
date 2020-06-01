def is_scan_packet_1(options, window):
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

def is_scan_packet_2(options, window):
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

def is_scan_packet_3(options, window):
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
            print ("scan_packet_3")

    except IndexError:
        return False

def is_scan_packet_4(options, window):
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

def is_scan_packet_5(options, window):
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

def is_scan_packet_6(options, window):
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

def scan_options_1():
    return [('MSS', 1366), ('NOP', None), ('WScale', 8), ('SAckOK', b''), ('Timestamp', (1, 1))]

def scan_options_2():
    return [('MSS', 1366), ('NOP', None), ('WScale', 8), ('SAckOK', b''), ('Timestamp', (1, 1))]

def scan_options_3():
    return [('MSS', 1366), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('Timestamp', (1, 1))]

def scan_options_4():
    return [('MSS', 1366), ('NOP', None), ('WScale', 8), ('SAckOK', b''), ('Timestamp', (1, 1))]

def scan_options_5():
    return [('MSS', 1366), ('NOP', None), ('WScale', 8), ('SAckOK', b''), ('Timestamp', (1, 1))]

def scan_options_6():
    return [('MSS', 1366), ('SAckOK', b''), ('Timestamp', (1, 1))]

