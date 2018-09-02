import tools.number

def is_port(port):
    """
    Helper function to return True if the string passed is a an
    integer between 1 and 65535 and False otherwise.
    """

    if tools.number.is_integer(port):
        if (int(port) >= 1 and int(port) <= 65535):
            return True
    return False

def is_port_range(port_range):
    """
    Helper function to return True if the string passed is a valid range
    of integers between 1 and 65535 in the format of ...
        XXXXX-XXXXX
    ... and return False otherwise.
    """ 

    ports = port_range.split('-')
    if len(ports) == 2:
        if is_port(ports[0]) and is_port(ports[1]):
            if (int(ports[0]) < int(ports[1]) ):
                return True
    return False

def port_list(port_range):
    """
    Helper function to return a list of ports. The function accepts
    strings containing a valid port or port range.
    """

    if is_port(port_range):
        return [port_range]

    elif is_port_range(port_range):
        start_port, end_port = port_range.split('-')

        port_list = []
        for port in range(int(start_port), int(end_port)+1):
            port_list.append(str(port))
        return port_list

