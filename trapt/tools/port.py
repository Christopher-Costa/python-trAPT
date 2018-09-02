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
