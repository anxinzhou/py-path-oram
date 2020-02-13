def prefix_pad_zero(data, length):
    if len(data) >= length:
        return data
    return ('0'*length + data)[-len(data):]