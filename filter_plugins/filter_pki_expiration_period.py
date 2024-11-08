import struct

def to_pki_expiration_period(period_dict):
    # Convert time periods to total seconds
    total_seconds = (
        (period_dict.get('years', 0) * 31536000) +
        (period_dict.get('months', 0) * 2592000) +
        (period_dict.get('weeks', 0) * 604800) +
        (period_dict.get('days', 0) * 86400) +
        (period_dict.get('hours', 0) * 3600)
    )

    # Convert to PKI period (negative 100-nanosecond intervals) and to bytes
    pki_period = round(total_seconds * -10000000)
    return list(struct.pack("<q", pki_period))

class FilterModule(object):
    def filters(self):
        return {
            'to_pki_expiration_period': to_pki_expiration_period
        }