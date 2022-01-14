#!/bin/bash

kli status --name gleif > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists, launching GLEIF agent."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name gleif --file scripts/pilot/gleif-incept.json
  kli vc registry incept --name gleif --registry-name gleif
fi

kli status --name qvi > /dev/null 2>&1

if [ $? -eq 0 ]
then
  echo "Identifier prefix exists."
else
  echo "Identifier prefix does not exist, running incept"
  kli incept --name qvi --file scripts/pilot/qvi-incept.json
  kli vc registry incept --name qvi --registry-name qvi
fi

echo "Launching QVI agent"
kli pilot qvi
