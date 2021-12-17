# -*- encoding: utf-8 -*-
"""
KERI
keri.app.cli.commands.bootstrap module

"""
import argparse
import os
import sys

import falcon
from hio.base import doing
from hio.core import http

parser = argparse.ArgumentParser()
parser.set_defaults(handler=lambda args: launch())

WEB_DIR_PATH = os.path.dirname(
    os.path.abspath(
        sys.modules.get(__name__).__file__))
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'ui')

def launch(path=STATIC_DIR_PATH):
    app = falcon.App()

    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    server = http.Server(port=5678, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    doers = [httpServerDoer]
    tock = 0.03125
    doist = doing.Doist(limit=0.0, tock=tock, real=True)
    doist.do(doers=doers)

