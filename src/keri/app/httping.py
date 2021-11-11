# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import json
from dataclasses import dataclass

import falcon
from hio.help import Hict

from keri import help
from keri import kering
from keri.core import coring
from keri.core.coring import Ilks
from keri.db import dbing
from keri.end import ending
from keri.help.helping import nowIso8601

logger = help.ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"
CESR_DATE_HEADER = "CESR-DATE"
CESR_RECIPIENT_HEADER = "CESR-RECIPIENT"


class Diagnostician:
    """
    Diagnostic endpoints for a running agent or witness or watcher.  Provides escrow contents
    for the key event log database as well as escrows for the verifiable credential and transaction
    event log database.


    """

    def __init__(self, db, reger, app=None):
        self.db = db
        self.reger = reger

        self.app = app if app is not None else falcon.App(cors_enable=True)

        self.app.add_route("/escrows", self, suffix="escrows")


    def on_get_escrows(self, req, rep):
        """ Diagnostic endpoint to return the current state of database escrows

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        pre = req.params["pre"] if "pre" in req.params else None
        escrow = req.params["escrow"] if "escrow" in req.params else None

        escrows = dict()

        oots = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:
            for ekey, edig in self.db.getOoeItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                oots.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["out-of-order"] = oots

        uwes = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, ecouple in self.db.getUweItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow db key
                uwes.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["unverified-witness-receipts"] = uwes

        ures = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, etriplet in self.db.getUreItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                ures.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["unverified-nontrans-receipts"] = ures


        vres = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, equinlet in self.db.getVreItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                vres.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["unverified-trans-receipts"] = vres

        pwes = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getPweItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                pwes.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["partially-witnessed-events"] = pwes

        pses = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getPseItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                pses.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["partially-signed-events"] = pses

        ldes = list()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getLdeItemsNextIter(key=key):
                pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                ldes.append(dict(pre=pre.decode("utf-8"), sn=sn))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

        escrows["likely-duplicitous-events"] = ldes


        rtaes = list()
        ctaes = list()
        for (pre, snb, digb) in self.reger.getTaeItemIter():
            sn = int(snb, 16)
            dgkey = dbing.dgKey(pre, digb)
            traw = self.reger.getTvt(dgkey)
            if traw is None:
                continue

            tserder = coring.Serder(raw=bytes(traw))  # escrowed event
            if tserder.ked["t"] in (Ilks.vcp, Ilks.vrt):
                rtaes.append(dict(pre=pre.decode("utf-8"), sn=sn))
            else:
                ctaes.append(dict(pre=pre.decode("utf-8"), sn=sn))

        escrows["anchorless-registry-events"] = rtaes
        escrows["anchorless-credential-events"] = ctaes

        roots = list()
        coots = list()
        for (pre, snb, digb) in self.reger.getOotItemIter():
            sn = int(snb, 16)
            dgkey = dbing.dgKey(pre, digb)
            traw = self.reger.getTvt(dgkey)
            if traw is None:
                continue

            tserder = coring.Serder(raw=bytes(traw))  # escrowed event
            if tserder.ked["t"] in (Ilks.vcp, Ilks.vrt):
                roots.append(dict(pre=pre.decode("utf-8"), sn=sn))
            else:
                coots.append(dict(pre=pre.decode("utf-8"), sn=sn))

        escrows["out-of-order-registry-events"] = roots
        escrows["out-of-order-credential-events"] = coots

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(escrows, indent=2).encode("utf-8")




class SignatureValidationComponent(object):

    def __init__(self, hab, pre):
        self.hab = hab
        self.pre = pre

    def process_request(self, req, resp):
        sig = req.headers.get("SIGNATURE")

        ser = req.bounded_stream.read()
        if not self.validate(sig=sig, ser=ser):
            resp.complete = True
            resp.status = falcon.HTTP_401
            return
        req.context.raw = ser

    def validate(self, sig, ser):
        signages = ending.designature(sig)
        markers = signages[0].markers

        if self.pre not in self.hab.kevers:
            return False

        verfers = self.hab.kevers[self.pre].verfers
        for idx, verfer in enumerate(verfers):
            key = str(idx)
            if key not in markers:
                return False
            siger = markers[key]
            siger.verfer = verfer

            if not verfer.verify(siger.raw, ser):
                return False

        return True




@dataclass
class CesrRequest:
    resource: str
    date: str
    payload: dict
    modifiers: dict
    attachments: str


def parseCesrHttpRequest(req, prefix=None):
    """
    Parse Falcon HTTP request and create a CESR message from the body of the request and the two
    CESR HTTP headers (Date, Attachment).

    Parameters
        req (falcon.Request) http request object in CESR format:

    """
    if req.content_type != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(falcon.HTTP_NOT_ACCEPTABLE,
                               title="Content type error",
                               description="Unacceptable content type.")

    try:
        data = json.load(req.bounded_stream)
    except ValueError:
        raise falcon.HTTPError(falcon.HTTP_400,
                               title="Malformed JSON",
                               description="Could not decode the request body. The "
                                           "JSON was incorrect.")

    resource = req.path
    if prefix is not None:
        resource = resource.removeprefix(prefix)

    if CESR_DATE_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_UNAUTHORIZED,
                               title="Date error",
                               description="Missing required date header.")

    dt = req.headers[CESR_DATE_HEADER]

    if CESR_ATTACHMENT_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_PRECONDITION_FAILED,
                               title="Attachment error",
                               description="Missing required attachment header.")
    attachment = req.headers[CESR_ATTACHMENT_HEADER]


    cr = CesrRequest(
        resource=resource,
        date=dt,
        payload=data,
        modifiers=req.params,
        attachments=attachment)

    return cr


def createCESRRequest(msg, client, date=None):
    """
    Turns a KERI message into a CESR http request against the provided hio http Client

    Parameters
       msg:  KERI message parsable as Serder.raw
       client: hio http Client that will send the message as a CESR request

    """

    dt = date if date is not None else nowIso8601()
    try:
        serder = coring.Serder(raw=msg)
    except kering.ShortageError as ex:  # need more bytes
        raise kering.ExtractionError("unable to extract a valid message to send as HTTP")
    else:  # extracted successfully
        del msg[:serder.size]  # strip off event from front of ims

    ilk = serder.ked["t"]
    attachments = bytearray(msg)
    query = serder.ked["q"] if "q" in serder.ked else None

    if ilk in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt, Ilks.ksn, Ilks.rct):
        resource = "/kel"
        body = serder.raw
    elif ilk in (Ilks.qry, ):
        resource = "/" + ilk + "/" + serder.ked['r']
        body = serder.raw
    elif ilk in (Ilks.fwd,):
        resource = "/" + ilk + "/" + serder.ked['r']
        body = json.dumps(serder.ked["a"]).encode("utf-8")
    elif ilk in (Ilks.exn,):
        resource = "/" + ilk + serder.ked['r']
        body = json.dumps(serder.ked["d"]).encode("utf-8")
        dt = serder.ked["dt"]
    elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
        resource = "/tel"
        body = serder.raw
    else:
        raise kering.InvalidEventTypeError("Event type {} is not handled by http clients".format(ilk))

    headers = Hict([
        ("Content-Type", CESR_CONTENT_TYPE),
        ("Content-Length", len(body)),
        (CESR_DATE_HEADER, dt),
        (CESR_ATTACHMENT_HEADER, attachments)
    ])

    client.request(
        method="POST",
        path=resource,
        qargs=query,
        headers=headers,
        body=body
    )


class InsecureSignatureComponent(object):

    def process_request(self, req, resp):
        ser = req.bounded_stream.read()
        req.context.raw = ser
