import argparse
import logging

from hio.base import doing
from keri.app import habbing, indirecting, directing
from keri.app.cli.commands.agent import start
from keri.app.cli.commands.incept import InceptDoer
from keri.app.cli.commands.vc.registry import incept

parser = argparse.ArgumentParser(description="Run a demo collection of witnesses")
parser.set_defaults(handler=lambda args: demo(args))


# help.ogler.level = logging.INFO
# logger = help.ogler.getLogger()


def demo(args):
    with habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False, temp=False) as wanHab, \
            habbing.openHab(name="wil", salt=b'will-the-witness', transferable=False, temp=False) as wilHab, \
            habbing.openHab(name="wes", salt=b'wess-the-witness', transferable=False, temp=False) as wesHab:
        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=False, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=False, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=False, tcpPort=5634, httpPort=5644)

        doers = wanDoers + wilDoers + wesDoers

        gkwa = dict(
            salt="0123456789xgleif",
            transferable=True,
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            icount=1,
            ncount=1,
            isith=1,
            nsith=1
        )
        gleifIcpDoer = InceptDoer(name="gleif", proto="http", **gkwa)

        qkwa = dict(
            salt="issuer0000000001",
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            transferable=True,
            icount=1,
            ncount=1,
            isith=1,
            nsith=1
        )
        qviIcpDoer = InceptDoer(name="qvi", proto="http", **qkwa)

        pd = PilotDoer(gleif=gleifIcpDoer, qvi=qviIcpDoer)

        doers.extend([gleifIcpDoer, qviIcpDoer, pd])
        directing.runController(doers, expire=0.0)


class PilotDoer(doing.DoDoer):

    def __init__(self, gleif, qvi, **kwa):
        self.gleif = gleif
        self.qvi = qvi
        doers = [doing.doify(self.pilotDo)]
        super(PilotDoer, self).__init__(doers=doers, **kwa)

    def pilotDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            _ = yield self.tock

            if self.gleif.done:
                print("GLEIF incepted, creating registry")
                #   kli vc registry incept --name gleif --registry-name gleif
                gleifReg = incept.RegistryInceptor(name="gleif", registryName="gleif", estOnly=False, noBackers=True,
                                                   baks=[])

                self.extend([gleifReg])
                while not gleifReg.done:
                    _ = yield 1.0

                print()
                print("GLEIF registry created, starting agent...")
                # kli agent start --name gleif --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure
                # --tcp 5921 --admin-http-port 5923 --path=../kiwi/dist-gleif
                doers = start.runAgent(controller="E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM",
                                       name="gleif", insecure=True,
                                       tcp=5921, path="../kiwi/dist-gleif",
                                       adminHttpPort=5923)
                self.extend(doers)
                break

        while True:
            _ = yield self.tock
            if self.qvi.done:
                print("QVI incepted, creating registry...")
                #   kli vc registry incept --name gleif --registry-name gleif
                qviReg = incept.RegistryInceptor(name="qvi", registryName="qvi", estOnly=False, noBackers=True,
                                                 baks=[])
                self.extend([qviReg])
                while not qviReg.done:
                    _ = yield 1.0

                print()
                print("QVI registry created, starting agent...")
                # kli agent start --name qvi --controller E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM --insecure
                # --tcp 5621 --admin-http-port 5623 --path=../kiwi/dist-qvi
                doers += start.runAgent(controller="E4Zq5dxbnWKq5K-Bssn4g_qhBbSwNSI2MH4QYnkEUFDM",
                                        name="qvi", insecure=True,
                                        tcp=5621, path="../kiwi/dist-qvi",
                                        adminHttpPort=5623)

                self.extend(doers)
                break
        return True
