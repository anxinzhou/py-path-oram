def prefix_pad_dummy(data, length, dummy_symbol='0'):
    if len(data) > length:
        raise Exception("length of data is greater than length")
    return (dummy_symbol * length + data)[-length:]


def suffix_pad_dummy(data, length, dummy_symbol='#'):
    if len(data) > length:
        raise Exception("length of data is greater than length")
    return (data + dummy_symbol * length)[:length]
