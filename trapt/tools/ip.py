import ipaddress

def is_ipv4_address(ipv4_address):
    """
    Helper function to return True if the string passed is a valid
    IPv4 address, and False otherwise.
    """

    try:
        if ipaddress.ip_address(ipv4_address):
            return True
        return False

    except ValueError:
        return False

def is_ipv4_range(ipv4_range):
    """
    Helper function to return True is the string passed is a valid range
    of IPv4 addresses in the format of ...
        XXX.XXX.XXX.XXX-YYY.YYY.YYY.YYY
    .. and return False otherwise
    """

    ipv4_addresses = ipv4_range.split('-')

    if len(ipv4_addresses) != 2: 
        return False

    if is_ipv4_address(ipv4_addresses[0]) and is_ipv4_address(ipv4_addresses[-1]):
        return True
    return False

def ipv4_address_list(ipv4_range):
    """
    Helper function to return a list of IPv4 addresses. The function accepts
    strings containing valid IPv4 addresses or IPv4 address ranges
    """

    if is_ipv4_address(ipv4_range):
        return [ipv4_range]

    elif is_ipv4_range(ipv4_range):
        start_address, end_address = ipv4_range.split('-')

        ipv4_list = []
        for addr in range(int(ipaddress.ip_address(start_address)), int(ipaddress.ip_address(end_address))+1):
            ipv4_list.append(str(ipaddress.ip_address(addr)))
        return ipv4_list
