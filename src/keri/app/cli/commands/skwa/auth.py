# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help

from keri.app import habbing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Display current signing private key and next key hash')
parser.set_defaults(handler=lambda args: skwaAuth(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)


def skwaAuth(args):

    name = args.name
    try:
        with habbing.existingHab(name=name) as hab:

            if hab.kever.delegated:
                print("{} is a delegated identifier which is not supported for SKWA".format(hab.name))
                return -1

            if len(hab.kever.verfers) != 1:
                print("{} has multiple keys which is not supported for SKWA".format(hab.name))
                return -1

            if hab.group() is not None:
                print("{} has is part of a multisig group which is not supported for SKWA".format(hab.name))
                return -1

            if len(hab.kever.wits) != 0:
                print("{} has witnesses which are not supported for SKWA".format(hab.name))
                return -1

            if not hab.kever.estOnly:
                print("{} must be defined as establishment events only to support SKWA".format(hab.name))
                return -1


            print("Prefix:\t{}".format(hab.pre))
            print("Seq No:\t{}".format(hab.kever.sn))

            print()
            print("Next Key:")
            print("\t{}".format(hab.kever.nexter.qb64))

            pub = hab.kever.verfers[0].qb64b
            signer = hab.ks.pris.get(pub, decrypter=hab.mgr.decrypter)
            print("Signing Private Key:")
            print("\t{}".format(signer.qb64))



    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
