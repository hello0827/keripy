# -*- encoding: utf-8 -*-
"""
KERI
keri.app.apping module

"""
import json
from dataclasses import dataclass, asdict
from typing import Type, Union

import cbor2
import msgpack

from .. import help
from ..help import helping
from ..core import coring
from ..app  import keeping
from . import dbing



logger = help.ogler.getLogger()


class Komer:
    """
    Keyspace Object Mapper factory class
    """

    def __init__(self,
                 db: Type[dbing.LMDBer],
                 schema: Type[dataclass],
                 subdb: str = 'docs.',
                 kind: str = coring.Serials.json):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (dataclass):  reference to Class definition for dataclass sub class
            subdb (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        self.db = db
        self.schema = schema
        self.sdb = self.db.env.open_db(key=subdb.encode("utf-8"))
        self.kind = kind
        self.serializer = self._serializer(kind)
        self.deserializer = self._deserializer(kind)

    def put(self, keys: Union[tuple, str], data: dataclass):
        """
        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            data (dataclass): instance of dataclass of type self.schema as value
        """
        if not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))
        if isinstance(keys, str):
            keys = (keys, )  # make a tuple

        self.db.putVal(db=self.sdb,
                       key=".".join(keys).encode("utf-8"),
                       val=self.serializer(data))

    def get(self, keys: Union[tuple, str]):
        """
        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        if isinstance(keys, str):
            keys = (keys, )  # make a tuple

        data = helping.datify(self.schema,
                              self.deserializer(
                                  self.db.getVal(db=self.sdb,
                                                 key=".".join(keys).encode("utf-8"))))

        if data is None:
            return

        if not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))

        return data

    def rem(self, keys: Union[tuple, str]):
        """
        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        if isinstance(keys, str):
            keys = (keys, )  # make a tuple

        self.db.delVal(db=self.sdb,
                       key=".".join(keys).encode("utf-8"))


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            data = helping.datify(self.schema, self.deserializer(val))

            if not isinstance(data, self.schema):
                raise ValueError("Invalid schema type={} of data={}, expected {}."
                                 "".format(type(data), data, self.schema))
            keys = tuple(key.decode("utf-8").split('.'))
            yield (keys, data)


    def _serializer(self, kind):
        """
        Parameters:
            kind (str): serialization
        """
        if kind == coring.Serials.mgpk:
            return self.__serializeMGPK
        elif kind == coring.Serials.cbor:
            return self.__serializeCBOR
        else:
            return self.__serializeJSON

    def _deserializer(self, kind):
        """
        Parameters:
            kind (str): deserialization
        """
        if kind == coring.Serials.mgpk:
            return self.__deserializeMGPK
        elif kind == coring.Serials.cbor:
            return self.__deserializeCBOR
        else:
            return self.__deserializeJSON

    @staticmethod
    def __deserializeJSON(val):
        if val is None:
            return
        return json.loads(bytes(val).decode("utf-8"))

    @staticmethod
    def __deserializeMGPK(val):
        if val is None:
            return
        return msgpack.loads(bytes(val))

    @staticmethod
    def __deserializeCBOR(val):
        if val is None:
            return
        return cbor2.loads(bytes(val))

    @staticmethod
    def __serializeJSON(val):
        if val is None:
            return
        return json.dumps(asdict(val), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def __serializeMGPK(val):
        if val is None:
            return
        return msgpack.dumps(asdict(val))

    @staticmethod
    def __serializeCBOR(val):
        if val is None:
            return
        return cbor2.dumps(asdict(val))
