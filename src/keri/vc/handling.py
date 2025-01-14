# -*- encoding: utf-8 -*-
"""
keri.vc.handling module

"""

from hio.base import doing
from hio.help import decking

from keri import kering
from keri.help import helping
from keri.vdr import issuing, viring
from . import proving
from .. import help
from ..app import agenting, signing
from ..core import scheming, parsing
from ..kering import ShortageError
from ..peer import exchanging
from ..vc.proving import Credentialer

logger = help.ogler.getLogger()


class OfferHandler(doing.Doer):
    """
    Sample handler to a credential offer message from an Issuer to a Holder for a credential based

    on
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/credential/offer"                                // resource with nested namespace
           "q": {
              "issuer": "did:keri:EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"
              "output_descriptors: [
                 "EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA"
              ],
              "format": {
                "cesr": {
                  "proof_type": ["Ed25519Signature2018"]
                }
              }
           } //embedded credential_manifest structure, may contain presentation_definition of reqs for fullfilment
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/credential/offer"

    def __init__(self, wallet, formats, cues=None, **kwa):
        """

        Parameters:
            wallet (Wallet) credential wallet that will hold the issued credentials
            formats (list) of format str names accepted for offers
            cues (Optional(decking.Deck)): outbound cue messages

        """
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.wallet = wallet
        self.formats = formats

        super(OfferHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                recipient = msg["pre"]

                issuer = payload["issuer"]
                descriptors = payload["input_descriptors"]
                formats = payload["format"]

                schema = descriptors[0]

                fmts = []
                for fmt in self.formats:
                    if fmt in formats:
                        fmts.append(formats[fmt])

                if not fmts:
                    logger.info("No acceptable formats being offered in {}.  Needed one of {}."
                                "".format(formats, self.formats))
                    continue

                apply = credential_apply(issuer, schema, fmts, body={})

                exn = exchanging.exchange(route="/credential/apply", payload=apply)
                self.cues.append(dict(dest=recipient, rep=exn))

                yield

            yield


class ApplyHandler(doing.DoDoer):
    """
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/credential/apply"
           "q" {
              "issuer": "did:keri:EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"
              "input_descriptors": [
                 "EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA"
              ],
              "format": {
                 "cesr": {
                   "proof_type": ["Ed25519Signature2018"]
                 }
              }
           } //embedded credential_submission, may contain credential_fullfilment responding to presentation_def above
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/credential/apply"

    def __init__(self, hab, verifier, name, issuerCues=None, cues=None, **kwa):
        """ Initialize instance

        Parameters:
            hab (Habitat): credential wallet that will hold the issued credentials
            verifier (Verifier): Local credential verifier used to verify and save any issued credential
            name (str): local alias of issuer to use for issuing credential
            issuerCues (Optional(decking.Deck)): outbound cue messages for issuer
            cues (Optional(decking.Deck)): outbound cue messages
            **kwa (dict): keyword arguments passed to DoDoer

        """
        self.hab = hab
        self.verifier = verifier
        self.name = name
        self.issuer = None
        self.issuerCues = issuerCues if issuerCues is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.msgs = decking.Deck()

        super(ApplyHandler, self).__init__(doers=[doing.doify(self.escrowDo)], **kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        self.issuer = issuing.Issuer(hab=self.hab, name=self.name, reger=self.verifier.reger, cues=self.issuerCues)

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                recipientIdentifier = msg["pre"]

                payload = msg["payload"]

                schema = payload["schema"]
                issuer = payload["issuer"]
                source = []

                if issuer != self.hab.pre:
                    logger.info("request for incorrect issuer {} to {}".format(issuer, self.hab.pre))
                    continue

                if schema != scheming.QualifiedvLEIIssuervLEICredential:
                    logger.info("credential type {} is invalid, only QualifiedvLEIIssuervLEICredential can be "
                                "auto-issued".format(schema))
                    continue


                data = payload["body"]
                dt = data["dt"] if "dt" in data else helping.nowIso8601()

                d = dict(
                    d="",
                    i=recipientIdentifier.qb64,
                    dt=dt,
                )

                d |= data

                group = self.hab.group()
                if group is None:
                    pre = self.hab.pre
                else:
                    pre = group.gid

                creder = proving.credential(issuer=pre,
                                            schema=schema,
                                            subject=d,
                                            source=source,
                                            status=self.issuer.regk)
                try:
                    self.issuer.issue(creder=creder, dt=dt)
                except kering.MissingAnchorError:
                    logger.info("Missing anchor from credential issuance due to multisig identifier")

                craw = self.hab.endorse(creder)
                parsing.Parser().parse(ims=craw, vry=self.verifier)

                yield self.tock

            yield self.tock

    def escrowDo(self, tymth, tock=0.0):
        """ Processes the Groupy escrow for group icp, rot and ixn request messages.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list

        Returns:
            Doist: doifiable Doist compatible generator method

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            self.issuer.processEscrows()
            yield self.tock


class IssueHandler(doing.DoDoer):
    """ Sample class that handles a credential Issue `exn` message.

    By default, this handler verifies the credential with the provided verifier.
    The incoming message must have the following format:

         {
       "vc" [
         {
           "vc": {
              "v": "KERI10JSON00011c_", //KERI Version String
              "x": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the Schema
              "d": {
                   "type": [
                       "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI"
                   ],
                   "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                   "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",
                   "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                   "credentialSubject": {
                       "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                       "lei": "254900OPPU84GM83MG36"
                   },
                   "credentialSchema": {
                       "id": ""
                       "type": ""
                   },
                   "credentialStatus": {
                      "id": "",
                      "type": ""
                   }
              }
           }, // embedded verifiable credential
           "proof": "-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE
                 -d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA"
           }
       ]   //list of verifiable credentials
    }


    """

    resource = "/credential/issue"

    def __init__(self, hab, verifier,  cues=None, **kwa):
        """ Initialize instance

        Parameters:
            hab (Habitat): local identifier environment
            wallet (Wallet) credential wallet that will hold the issued credentials
            ims (Optional(bytearray)): inbound message stream to process
            cues (Optional(decking.Deck)): outbound cue messages
            **kwa (dict): keyword arguments passed to DoDoer

        """
        self.hab = hab
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.verifier = verifier
        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.HttpWitnesser)

        doers = [self.witq, doing.doify(self.msgDo)]

        super(IssueHandler, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth, tock=0.0):
        """ Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload (dict): representing the body of a /credential/issue message
            pre (qb64): identifier prefix of sender
            sigers (list): of Sigers representing the sigs on the /credential/issue message
            verfers (list): of Verfers of the keys used to sign the message

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                envelopes = payload["vc"]

                envelopes.reverse()
                for envlop in envelopes:
                    crd = envlop["vc"]
                    proof = envlop["proof"]

                    creder = proving.Credentialer(ked=crd)

                    msg = bytearray(creder.raw)
                    msg.extend(proof.encode("utf-8"))
                    parsing.Parser().parse(ims=msg, vry=self.verifier)

                    c = self.verifier.reger.saved.get(creder.said)
                    while c is None:
                        c = self.verifier.reger.saved.get(creder.said)
                        yield

                yield

            yield


class RequestHandler(doing.Doer):
    """ Processor for a credential request

        Processor for a credential request with input descriptors in the payload used to
        match saved credentials based on a schema.  The payload of the request is expected to
        have the following format:

             {
                ""submission_requirements": [{
                   "name": "Proof of LEI",
                   "rule": "pick",
                   "count": 1,
                   "from": "A"
                 }]
                "input_descriptors": [
                   {
                      "x":"EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA",
                      "group": ["A"],
                   }
                ],
                "format": {
                   "cesr": {
                     "proof_type": ["Ed25519Signature2018"]
                   }
                }
             }

    """

    resource = "/presentation/request"

    def __init__(self, hab, wallet, cues=None, **kwa):
        """ Create an `exn` request handler for processing credential presentation requests

        Parameters
            hab (Habitat): is the environment
            wallet (Wallet): is the wallet holding the credentials to present
            cues (Optional(decking.Deck)): outbound response cue for  this handler

        """
        self.hab = hab
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.wallet = wallet

        super(RequestHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process presentation request message with sender identifier, sigs and verfers

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload (dict): representing the body of a /presentation/request message
            pre (qb64): identifier prefix of sender
            sigers (list): of Sigers representing the sigs on the /presentation/request message
            verfers (list): of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                requestor = msg["pre"]
                descriptors = payload["input_descriptors"]

                matches = []
                for descriptor in descriptors:
                    schema = descriptor["s"]
                    credentials = self.wallet.getCredentials(schema)
                    if len(credentials) > 0:
                        matches.append(credentials[0])

                if len(matches) > 0:
                    pe = presentation_exchange(db=self.hab.db, reger=self.wallet.reger, credentials=matches)
                    exn = exchanging.exchange(route="/presentation/proof", payload=pe)
                    self.cues.append(dict(dest=requestor.qb64, rep=exn, topic="credential"))

                yield

            yield


class ProofHandler(doing.Doer):
    """ Processor for responding to presentation proof peer to peer message.

      The payload of the message is expected to have the following format:

        {
          "presentation_submission": {
              "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
              "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
              "descriptor_map": [
                   {
                     "id": "gleif_vlei",
                     "format": "cesr",
                     "path": "$.verifiableCredential[0]"
                   }
              ]
          },
          "verifiableCredential": [
              {
                "vc": {
                   "v": "KERI10JSON00011c_", //KERI Version String
                   "x": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the Schema
                   "q": {
                        "type": [
                            "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI"
                        ],
                        "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                        "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of
                        the issuer
                        "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                        "credentialSubject": {
                            "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                            "lei": "254900OPPU84GM83MG36"
                        }
                    } // embedded verifiable credential
                }
                "proof": "-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE
                -YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI
                -AABAALK_6pkUjCx76CTE7pNrKlhC84ewgZbs-4ciTvLcxkwUaWX7ukpr55P9RtJhlHxdtz3kN0zfM0HrtFitKuPy3BA"
              }
           ]
        }
    """

    resource = "/presentation/proof"

    def __init__(self, cues=None, proofs=None, **kwa):
        """ Initialize instance

        Parameters:
            cues (decking.Deck): outbound cue messages
            proofs (decking.Deck): inbound proof request `exn` messages
            **kwa (dict): keyword arguments passes to super Doer

        """
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.proofs = proofs if proofs is not None else decking.Deck()

        super(ProofHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Handle incoming messages by parsing and verifying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message


        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                pre = msg["pre"]

                if "presentation_submission" not in payload:
                    raise ValueError("invalid presentation proof payload")

                if "verifiableCredential" not in payload:
                    raise ValueError("invalid presentation proof payload")

                pe = payload["presentation_submission"]
                vcs = payload["verifiableCredential"]

                if "descriptor_map" not in pe:
                    raise ValueError("invalud presentation submission in proof payload")

                # TODO:  Find verifiable credential in vcs based on `path`
                dm = pe["descriptor_map"]
                print(dm)

                vcs.reverse()
                for vc in vcs:
                    self.proofs.append((pre, vc))

                yield

            yield


def envelope(msg, msgs=bytearray()):
    """ Returns a dict of a VC split into the "vc" and "proof"

    Parameters:
        msg (bytes): of verifiable credential to split
        msgs (bytearray) optional event log messages in support of the credential

    Returns:
        dict: enveloped credential, proof and key event/transaction event log messages

    """


    ims = bytearray(msg)
    try:
        creder = Credentialer(raw=ims)
    except ShortageError as e:
        raise e
    else:
        del ims[:creder.size]

    return dict(
        vc=creder.crd,
        proof=ims.decode("utf-8"),
        msgs=msgs.decode("utf-8")
    )


def presentation_exchange(db, reger, credentials):
    """ Create a presentation exchange.

    Create presentation exchange body containing the credential and event logs
    needed to provide proof of holding a valid credential

    Parameters:
        db (Baser): is the environment database
        reger (Registry): is the credential registry database
        credentials (list): is the list of credential instances

    Returns:
        dict: presentation dict for credential

    """
    dm = []
    vcs = []

    for idx, (creder, sadsigers, sadcigars) in enumerate(credentials):
        said = creder.said
        regk = creder.status
        vci = viring.nsKey([regk, said])

        issr = creder.crd["i"]

        msgs = bytearray()
        for msg in db.clonePreIter(pre=issr):
            msgs.extend(msg)

        for msg in reger.clonePreIter(pre=regk):
            msgs.extend(msg)

        for msg in reger.clonePreIter(pre=vci):
            msgs.extend(msg)

        # TODO:  Package credential in presentation exchange, transposing all signatures:
        dm.append(dict(
            id=creder.schema,
            format="cesr",
            path="$.verifiableCredential[{}]".format(idx)
        ))
        craw = signing.provision(creder, sadsigers=sadsigers, sadcigars=sadcigars)
        vcs.append(envelope(craw, msgs))

        sources = reger.sources(db, creder)
        vcs.extend([envelope(msg=craw, msgs=msgs) for craw, msgs in sources])


    d = dict(
        presentation_submission=dict(
            descriptor_map=dm
        ),
        verifiableCredential=vcs,
    )

    return d


def credential_apply(issuer, schema, formats, body):
    """ Creates credential apply body for `exn` message

    Resulting `exn` message will have the following format:
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/credential/apply"
           "q" {
              "issuer": "did:keri:EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"
              "schema": "E_xp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaL5d",
              "body": {
                 // fields specific to the credential specified in the input_descriptor
              }
           } //embedded credential_submission, may contain credential_fullfilment responding to presentation_def above
        }

    Parameters:
        issuer (str): is qb64 identifier prefix of the issuer
        schema (str): is qb64 SAID of schema being applied for
        formats (list): is list of acceptable credential formats
        body (map)" of values being applied for

    Returns:
        dict: field for credential apply body

    """

    d = dict(
        issuer=issuer,
        schema=schema,
        body=body
    )

    for fmt in formats:
        d["format"].append(fmt.fmd)

    return d


def credential_issue(msgs):
    """ Returns a list of credentials enveloped inside a credential issue message

    Parameters:
        msgs (list) is list of CESR formatted, endorsed verifiable credentials

    Returns:
        dict: vc list embedded in vc property

    """

    vcs = []
    for msg in msgs:
        vc = envelope(msg)
        vcs.append(vc)

    pl = dict(
        vc=vcs
    )

    return pl
