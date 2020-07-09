# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
import pytest
import pysodium
import blake3
import json

import msgpack
import cbor2 as cbor

from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

from keri.kering import Version, Versionage
from keri.core.coring import CrySelect, CryOne, CryTwo, CryFour, CryMat
from keri.core.coring import IntToB64, B64ToInt, SigTwo, SigTwoSizes, SigMat
from keri.core.coring import Serialage, Serials, Mimes, Vstrings
from keri.core.coring import Versify, Deversify, Rever, Serder
from keri.core.coring import Ilkage, Ilks, Corver


def test_derivationcodes():
    """
    Test the support functionality for derivation codes
    """
    assert CrySelect.two == '0'

    assert 'A' not in CrySelect

    for x in ['0']:
        assert x in CrySelect

    assert CryOne.Ed25519N == 'A'
    assert CryOne.X25519 == 'B'
    assert CryOne.Ed25519 == 'C'
    assert CryOne.Blake3_256 == 'D'
    assert CryOne.Blake2b_256 == 'E'
    assert CryOne.Blake2s_256 == 'F'
    assert CryOne.ECDSA_256k1N == 'G'
    assert CryOne.ECDSA_256k1 == 'H'
    assert CryOne.SHA3_256 == 'I'
    assert CryOne.SHA2_256 == 'J'

    assert '0' not in CryOne

    for x in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']:
        assert x in CryOne

    assert CryTwo.Ed25519 == '0A'
    assert CryTwo.ECDSA_256k1 == '0B'

    assert 'A' not in CryTwo

    for x in ['0A', '0B']:
        assert x in CryTwo

    assert '0' not in CryFour
    assert 'A' not in CryFour
    assert '0A' not in CryFour

    for x in []:
        assert x in CryFour


    """
    Done Test
    """

def test_crymat():
    """
    Test the support functionality for cryptographic material
    """
    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
    prebin = (b'\x01\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@'
              b'\xa13Y\x1fu\x0b\xbd\x80\x1fIS\xf3\x874\xbao\x90\x8c')

    with pytest.raises(ValueError):
        crymat = CryMat()

    crymat = CryMat(raw=verkey)
    assert crymat.raw == verkey
    assert crymat.code == CryOne.Ed25519N
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin

    assert crymat.qb64 == encodeB64(crymat.qb2).decode("utf-8")
    assert crymat.qb2 == decodeB64(crymat.qb64.encode("utf-8"))

    crymat._exfil(prefix)
    assert crymat.code == CryOne.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb64=prefix)
    assert crymat.code == CryOne.Ed25519N
    assert crymat.raw == verkey

    crymat = CryMat(qb2=prebin)
    assert crymat.code == CryOne.Ed25519N
    assert crymat.raw == verkey

    # test prefix on full identifier
    full = prefix + ":mystuff/mypath/toresource?query=what#fragment"
    crymat = CryMat(qb64=full)
    assert crymat.code == CryOne.Ed25519N
    assert crymat.raw == verkey
    assert crymat.qb64 == prefix
    assert crymat.qb2 == prebin

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64 = encodeB64(sig).decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0AmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qbin = (b'\xd0\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    crymat = CryMat(raw=sig, code=CryTwo.Ed25519)
    assert crymat.raw == sig
    assert crymat.code == CryTwo.Ed25519
    assert crymat.qb64 == qsig64
    assert crymat.qb2 == qbin

    crymat = CryMat(qb64=qsig64)
    assert crymat.raw == sig
    assert crymat.code == CryTwo.Ed25519

    crymat = CryMat(qb2=qbin)
    assert crymat.raw == sig
    assert crymat.code == CryTwo.Ed25519



    """
    Done Test
    """

def test_sigmat():
    """
    Test the support functionality for attached signature cryptographic material
    """
    assert SigTwo.Ed25519 ==  'A'  # Ed25519 signature.
    assert SigTwo.ECDSA_256k1 == 'B'  # ECDSA secp256k1 signature.

    assert SigTwoSizes[SigTwo.Ed25519] == 88
    assert SigTwoSizes[SigTwo.ECDSA_256k1] == 88

    cs = IntToB64(80)
    assert cs ==  "BQ"
    i = B64ToInt(cs)
    assert i ==  80

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    sig64 = encodeB64(sig).decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qbin = decodeB64(qsig64.encode("utf-8"))
    assert len(qbin) == 66
    assert qbin == (b'\x00\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
                    b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
                    b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')


    sigmat = SigMat(raw=sig)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwo.Ed25519
    assert sigmat.index == 0
    assert sigmat.qb64 == qsig64
    assert sigmat.qb2 == qbin

    sigmat = SigMat(qb64=qsig64)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwo.Ed25519
    assert sigmat.index == 0

    sigmat = SigMat(qb2=qbin)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwo.Ed25519
    assert sigmat.index == 0

    sigmat = SigMat(raw=sig, code=SigTwo.Ed25519, index=5)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwo.Ed25519
    assert sigmat.index == 5
    qsig64 = 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert sigmat.qb64 == qsig64
    qbin = (b'\x00Y\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')
    assert sigmat.qb2 == qbin

    sigmat = SigMat(qb64=qsig64)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwo.Ed25519
    assert sigmat.index == 5

    sigmat = SigMat(qb2=qbin)
    assert sigmat.raw == sig
    assert sigmat.code == SigTwo.Ed25519
    assert sigmat.index == 5


    """
    Done Test
    """


def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """
    assert Version == Versionage(major=1, minor=0)

    assert isinstance(Serials, Serialage)

    assert Serials.json == 'JSON'
    assert Serials.mgpk == 'MGPK'
    assert Serials.cbor == 'CBOR'

    assert 'JSON' in Serials
    assert 'MGPK' in Serials
    assert 'CBOR' in Serials

    assert Mimes.json == 'application/keri+json'
    assert Mimes.mgpk == 'application/keri+msgpack'
    assert Mimes.cbor == 'application/keri+cbor'

    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'


    icp = dict(vs = Vstrings.json,
              id = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'icp',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              next = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              wits = [],
              data = [],
              sigs = [0]
             )

    rot = dict(vs = Vstrings.json,
              id = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'rot',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              next = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              cuts = [],
              adds = [],
              data = [],
              sigs = [0]
             )

    icps = json.dumps(icp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(icps) == 314
    assert icps == (b'{"vs":"KERI10JSON000000_","id":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"icp","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"next":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"wits":[],"data":[],"'
                    b'sigs":[0]}')

    match = Rever.search(icps)
    assert match.group() == Vstrings.json.encode("utf-8")

    rots = json.dumps(rot, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(rots) == 324
    assert rots == (b'{"vs":"KERI10JSON000000_","id":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"rot","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"next":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"cuts":[],"adds":[],"'
                    b'data":[],"sigs":[0]}')

    match = Rever.search(rots)
    assert match.group() == Vstrings.json.encode("utf-8")

    icp["vs"] = Vstrings.mgpk
    icps = msgpack.dumps(icp)
    assert len(icps) == 271
    assert icps == (b'\x8c\xa2vs\xb1KERI10MGPK000000_\xa2id\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS'
                    b'VPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3icp\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwyZ'
                    b'-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH'
                    b'3ULvYAfSVPzhzS6b5CM\xa4next\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4wits\x90\xa4data\x90\xa4sigs\x91\x00')

    match = Rever.search(icps)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    rot["vs"] = Vstrings.mgpk
    rots = msgpack.dumps(rot)
    assert len(rots) == 277
    assert rots == (b'\x8d\xa2vs\xb1KERI10MGPK000000_\xa2id\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS'
                    b'VPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3rot\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwyZ'
                    b'-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH'
                    b'3ULvYAfSVPzhzS6b5CM\xa4next\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4cuts\x90\xa4adds\x90\xa4data\x90\xa4sigs\x91\x00')

    match = Rever.search(rots)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    icp["vs"] = Vstrings.cbor
    icps = cbor.dumps(icp)
    assert len(icps) == 271
    assert icps == (b'\xacbvsqKERI10CBOR000000_bidx,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMb'
                    b'snd0001cilkcicpcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01d'
                    b'keys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMdnextx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dwits\x80ddata\x80dsigs\x81\x00')

    match = Rever.search(icps)
    assert match.group() == Vstrings.cbor.encode("utf-8")

    rot["vs"] = Vstrings.cbor
    rots = cbor.dumps(rot)
    assert len(rots) == 277
    assert rots == (b'\xadbvsqKERI10CBOR000000_bidx,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMb'
                    b'snd0001cilkcrotcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01d'
                    b'keys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMdnextx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dcuts\x80dadds\x80ddata\x80dsigs\x81'
                    b'\x00')

    match = Rever.search(rots)
    assert match.group() == Vstrings.cbor.encode("utf-8")

    """
    Done Test
    """

def test_serder():
    """
    Test the support functionality for Serder key event serialization deserialization
    """
    vs = Versify(kind=Serials.json, size=0)
    assert vs == "KERI10JSON000000_"
    kind, version, size = Deversify(vs)
    assert kind == Serials.json
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    kind, version, size = Deversify(vs)
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 65

    with pytest.raises(ValueError):
        serder = Serder()


    e1 = dict(vs=Vstrings.json, id="ABCDEFG", sn="0001", ilk="rot")
    serder = Serder(ked=e1)

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    vs = Versify(kind=Serials.json, size=len(e1s))  # use real length
    assert vs == 'KERI10JSON000041_'
    e1["vs"] = vs  # has real length
    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    kind1, vers1, size1 = serder._sniff(e1s)
    assert kind1 == Serials.json
    assert size1 == 65
    e1ss = e1s + b'extra attached at the end.'
    ked1, knd1, siz1 = serder._inhale(e1ss)
    assert ked1 == e1
    assert knd1 == kind1
    assert siz1 == size1

    raw1, knd1, ked1 = serder._exhale(ked=e1)
    assert raw1 == e1s
    assert knd1 == kind1
    assert ked1 == e1

    e2 = dict(e1)
    e2["vs"] = Vstrings.mgpk
    e2s = msgpack.dumps(e2)
    vs = Versify(kind=Serials.mgpk, size=len(e2s))  # use real length
    assert vs == 'KERI10MGPK000031_'
    e2["vs"] = vs  # has real length
    e2s = msgpack.dumps(e2)
    kind2, vers2, size2 = serder._sniff(e2s)
    assert kind2 == Serials.mgpk
    assert size2 == 49
    e2ss = e2s + b'extra attached  at the end.'
    ked2, knd2, siz2 = serder._inhale(e2ss)
    assert ked2 == e2
    assert knd2 == kind2
    assert siz2 == size2

    raw2, knd2, ked2 = serder._exhale(ked=e2)
    assert raw2 == e2s
    assert knd2 == kind2
    assert ked2 == e2

    e3 = dict(e1)
    e3["vs"] = Vstrings.cbor
    e3s = cbor.dumps(e3)
    vs = Versify(kind=Serials.cbor, size=len(e3s))  # use real length
    assert vs == 'KERI10CBOR000031_'
    e3["vs"] = vs  # has real length
    e3s = cbor.dumps(e3)
    kind3, vers3, size3 = serder._sniff(e3s)
    assert kind3 == Serials.cbor
    assert size3 == 49
    e3ss = e3s + b'extra attached  at the end.'
    ked3, knd3, siz3 = serder._inhale(e3ss)
    assert ked3 == e3
    assert knd3 == kind3
    assert siz3 == size3

    raw3, knd3, ked3 = serder._exhale(ked=e3)
    assert raw3 == e3s
    assert knd3 == kind3
    assert ked3 == e3

    evt1 = Serder(raw=e1ss)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]

    evt1 = Serder(ked=ked1)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]

    evt2 = Serder(raw=e2ss)
    assert evt2.kind == kind2
    assert evt2.raw == e2s
    assert evt2.ked == ked2

    evt2 = Serder(ked=ked2)
    assert evt2.kind == kind2
    assert evt2.raw == e2s
    assert evt2.ked == ked2
    assert evt2.size == size2
    assert evt2.raw == e2ss[:size2]

    evt3 = Serder(raw=e3ss)
    assert evt3.kind == kind3
    assert evt3.raw == e3s
    assert evt3.ked == ked3

    evt3 = Serder(ked=ked3)
    assert evt3.kind == kind3
    assert evt3.raw == e3s
    assert evt3.ked == ked3
    assert evt3.size == size3
    assert evt3.raw == e3ss[:size3]

    #  round trip
    evt2 = Serder(ked=evt1.ked)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size

    # Test change in kind by Serder
    evt1 = Serder(ked=ked1, kind=Serials.mgpk)  # ked is json but kind mgpk
    assert evt1.kind == kind2
    assert evt1.raw == e2s
    assert evt1.ked == ked2
    assert evt1.size == size2
    assert evt1.raw == e2ss[:size2]

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size


    evt1 = Serder(ked=ked1, kind=Serials.cbor)  # ked is json but kind mgpk
    assert evt1.kind == kind3
    assert evt1.raw == e3s
    assert evt1.ked == ked3
    assert evt1.size == size3
    assert evt1.raw == e3ss[:size3]

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size

    # use kind setter property
    assert evt2.kind == Serials.cbor
    evt2.kind = Serials.json
    assert evt2.kind == Serials.json
    knd, version, size = Deversify(evt2.ked['vs'])
    assert knd == Serials.json

    """
    Done Test
    """

def test_ilds():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt')

    assert isinstance(Ilks, Ilkage)

    assert Ilks.icp == 'icp'
    assert Ilks.rot == 'rot'
    assert Ilks.ixn == 'ixn'
    assert Ilks.dip == 'dip'
    assert Ilks.drt == 'drt'

    assert 'icp' in Ilks
    assert 'rot' in Ilks
    assert 'ixn' in Ilks
    assert 'dip' in Ilks
    assert 'drt' in Ilks


def test_event_manual():
    """
    Test manual process of key event message
    """
    with pytest.raises(ValueError):
        corver = Corver()

    # create qualified aid in basic format
    # workflow is start with seed and save seed. Seed in this case is 32 bytes
    # aidseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    aidseed = b'p6\xac\xb7\x10R\xc4\x9c7\xe8\x97\xa3\xdb!Z\x08\xdf\xfaR\x07\x9a\xb3\x1e\x9d\xda\xee\xa2\xbc\xe4;w\xae'
    assert len(aidseed) == 32

    # create and save verkey. Given we have sigseed and verkey then sigkey is
    # redundant, that is, sigkey = sigseed + verkey. So we can easily recreate
    # sigkey by concatenating sigseed + verkey.
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(aidseed)
    assert verkey == b'\xaf\x96\xb0p\xfb0\xa7\xd0\xa4\x18\xc9\xdc\x1d\x86\xc2:\x98\xf7?t\x1b\xde.\xcc\xcb;\x8a\xb0\xa2O\xe7K'
    assert len(verkey) == 32

    # create qualified aid in basic format
    aidmat = CryMat(raw=verkey, code=CryOne.Ed25519)
    assert aidmat.qb64 == 'Cr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'

    # create qualified next public key in basic format
    nxtseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    nxtseed = b'm\x04\xf9\xe4\xd5`<\x91]>y\xe9\xe5$\xb6\xd8\xd5D\xb7\xea\xf6\x13\xd4\x08TYL\xb6\xc7 D\xc7'
    assert len(nxtseed) == 32

    # create and save verkey. Given we have sigseed and verkey then sigkey is
    # redundant, that is, sigkey = sigseed + verkey. So we can easily recreate
    # sigkey by concatenating sigseed + verkey.
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(nxtseed)
    assert verkey == b'\xf5DOB:<\xcd\x16\x18\x9b\x83L\xa5\x0c\x98X\x90C\x1a\xb30O\xa5\x0f\xe39l\xa6\xdfX\x185'
    assert len(verkey) == 32

    # create qualified nxt key in basic format
    nxtkeymat = CryMat(raw=verkey, code=CryOne.Ed25519)
    assert nxtkeymat.qb64 == 'C9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'

    # create next hash
    nxtsith =  "{:x}".format(1)  # lowecase hex no leading zeros
    assert nxtsith == "1"
    nxts = []  # create list to concatenate for hashing
    nxts.append(nxtsith.encode("utf-8"))
    nxts.append(nxtkeymat.qb64.encode("utf-8"))
    nxtsraw = b''.join(nxts)
    assert nxtsraw == b'1C9URPQjo8zRYYm4NMpQyYWJBDGrMwT6UP4zlspt9YGDU'
    nxtdig = blake3.blake3(nxtsraw).digest()
    assert nxtdig == b'm>m\xa0\t\xe1\xfcO\xb8S\xe7\xfcvu\x82\xac&t6\xa2\x7f~\x8e\xaa\xd4v%\xbf>\xe5\x96\x1f'

    nxtdigmat = CryMat(raw=nxtdig, code=CryOne.Blake3_256)
    assert nxtdigmat.qb64 == 'DbT5toAnh_E-4U-f8dnWCrCZ0NqJ_fo6q1HYlvz7llh8'

    sn =  0
    sith = 1
    toad = 0

    #create key event dict
    ked0 = dict(vs=Versify(kind=Serials.json, size=0),
                id=aidmat.qb64,  # qual base 64 prefix
                sn="{:x}".format(sn),  # hex string no leading zeros lowercase
                ilk=Ilks.icp,
                sith="{:x}".format(sith), # hex string no leading zeros lowercase
                keys=[aidmat.qb64],  # list of signing keys each qual Base64
                next=nxtdigmat.qb64,  # hash qual Base64
                toad="{:x}".format(toad),  # hex string no leading zeros lowercase
                wits=[],  # list of qual Base64 may be empty
                data=[],  # list of config ordered mappings may be empty
                sigs=[]  # optional list of lowercase hex strings no leading zeros or single lowercase hex string
               )


    txsrdr = Serder(ked=ked0, kind=Serials.json)
    assert txsrdr.raw == (b'{"vs":"KERI10JSON000105_","id":"Cr5awcPswp9CkGMncHYbCOpj3P3Qb3i7MyzuKsKJP50s'
                          b'","sn":"0","ilk":"icp","sith":"1","keys":["Cr5awcPswp9CkGMncHYbCOpj3P3Qb3i7M'
                          b'yzuKsKJP50s"],"next":"DbT5toAnh_E-4U-f8dnWCrCZ0NqJ_fo6q1HYlvz7llh8","toad":"'
                          b'0","wits":[],"data":[],"sigs":[]}')

    assert txsrdr.size == 261

    sig0raw = pysodium.crypto_sign_detached(txsrdr.raw, aidseed + aidmat.raw)  #  sigkey = seed + verkey
    assert len(sig0raw) == 64

    """
    sig0raw = (b'Hu\xc5|V\xd8\x81\xe7(\xf9\xc4\xe5\xc9\xbe\xab\xeb\x17\xa45X\xaf\xd8FN'
               b'y\xe7\xee\\\x9c\xb4\x8a\xc3\xc4G\x8f\t\x91D\xd1\x80\xe0.\x01QR\xdc\x0e\xcd'
               b'\xba "\x16\x9b\xf2\xe5(\xa6\xfa\xbb\xf4(\x02\x95\n')

    """
    result = pysodium.crypto_sign_verify_detached(sig0raw, txsrdr.raw, aidmat.raw)
    assert not result

    txsigmat = SigMat(raw=sig0raw, code=SigTwo.Ed25519, index=0)
    assert txsigmat.qb64 == 'AAbtzfaUNKhDf84JFhLiw_JOaj8v1KhmZsd4aQYKJ4KyrpB2X_8cs31MGqJgMHj5-JY5l3OXLvphaHLvGzIs2PBg'
    assert len(txsigmat.qb64) == 88

    msgb = txsrdr.raw + txsigmat.qb64.encode("utf-8")

    assert len(msgb) == 349  #  261 + 88

    #  Recieve side
    rxsrdr = Serder(raw=msgb)

    """
    Done Test
    """

if __name__ == "__main__":
    test_event_manual()
