def is_integer(integer_string):
    """
    Helper function to return True if the string passed is a an
    integer and False otherwise.
    """

    try:
        if int(integer_string):
            return True
        return False

    except ValueError:
        return False
