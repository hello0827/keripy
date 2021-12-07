# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
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
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')

class Bootstrap:
    def on_get(self, req, rep):
        rep.content_type = falcon.MEDIA_TEXT  # Default is JSON, so override
        rep.text = ('\nTwo things awe me most, the starry sky '
                     'above me and the moral law within me.\n'
                     '\n'
                     '    ~ Immanuel Kant\n\n')
        rep.status = falcon.HTTP_200                     

    def on_post(self, req, rep):
        return falcon.HTTP_200


def launch():
    print(STATIC_DIR_PATH)
    app = falcon.App()

    app.add_route('/bootstrap', Bootstrap())
    sink = http.serving.StaticSink(staticDirPath=STATIC_DIR_PATH)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    server = http.Server(port=5678, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    doers = [httpServerDoer]
    tock = 0.03125
    doist = doing.Doist(limit=0.0, tock=tock, real=True)
    doist.do(doers=doers)


if __name__ == "__main__":
    print("launching bootstrap ", STATIC_DIR_PATH)
    launch()
