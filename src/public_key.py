from src.pyipv8.ipv8.keyvault.public.libnaclkey import LibNaCLPK

class PublicKey(object):

    def __init__(self, public_key):
        self.key = public_key

    def as_buffer(self):
        return buffer(self.key.key_to_bin())

    def as_bin(self):
        return str(self.key.key_to_bin())

    def as_hex(self):
        return self.as_bin().encode('hex')

    def as_readable(self):
        return self.as_hex()[-8:]

    @classmethod
    def from_bin(cls, bin_key):
        return cls(LibNaCLPK(bin_key[10:]))

    @classmethod
    def from_hex(cls, hex_key):
        return PublicKey.from_bin(hex_key.decode('hex'))
    
    def __eq__(self, other):
        return self.key.key.pk == other.key.key.pk

    def __neq__(self, other):
        return not self.__eq__(other)