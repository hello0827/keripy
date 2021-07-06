# -*- encoding: utf-8 -*-
"""
tests.vc.proving module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.coring import Serials, Counter, CtrDex, Prefixer, Seqner, Diger, Siger
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.vc.proving import Credentialer, credential


def test_proving():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS:
        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        assert sidHab.pre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"
        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(
            type="object",
            properties=dict(
                id=dict(
                    type="string"
                ),
                lei=dict(
                    type="string"
                )
            )
        ))

        schemer = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        credSubject = dict(
            id="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36"
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            issuance="2021-06-27T21:26:21.233257+00:00",
                            typ=JSONSchema(resolver=cache))

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000189_","x":"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o",'
            b'"d":{"id":"EvK-hjgQCltc-jk_FZPOj4f3S6yEuNRpQcrVTfk1UsCQ","type":['
            b'"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o"],'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00","credentialSubject":{'
            b'"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
            b'"lei":"254900OPPU84GM83MG36"}}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAAsPhz4tfZGgoV'
            b'-1gYtvI1QfzSxwItp5JvguLhKnZE27px5q9fcKGPC0GkMlMBaRyfC47Db4zEWG6ceQ98g6dWDA')

        creder = Credentialer(raw=msg, typ=JSONSchema(resolver=cache))
        proof = msg[creder.size:]

        ctr = Counter(qb64b=proof, strip=True)
        assert ctr.code == CtrDex.AttachedMaterialQuadlets
        assert ctr.count == 52

        pags = ctr.count * 4
        assert len(proof) == pags

        ctr = Counter(qb64b=proof, strip=True)
        assert ctr.code == CtrDex.TransIndexedSigGroups
        assert ctr.count == 1

        prefixer = Prefixer(qb64b=proof, strip=True)
        assert prefixer.qb64 == sidHab.pre

        seqner = Seqner(qb64b=proof, strip=True)
        assert seqner.sn == sidHab.kever.sn

        diger = Diger(qb64b=proof, strip=True)
        assert diger.qb64 == sidHab.kever.serder.dig

        ictr = Counter(qb64b=proof, strip=True)
        assert ictr.code == CtrDex.ControllerIdxSigs

        isigers = []
        for i in range(ictr.count):
            isiger = Siger(qb64b=proof, strip=True)
            isiger.verfer = sidHab.kever.serder.verfers[i]
            isigers.append(isiger)
        assert len(isigers) == 1

        siger = isigers[0]
        assert siger.verfer.verify(siger.raw, creder.raw) is True


if __name__ == '__main__':
    test_proving()