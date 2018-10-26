#!/usr/bin/python2

import sys
import os
import json

TESTS_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS_PATH, '../../py/'))

from nftables import Nftables

# Change working directory to repository root
os.chdir(TESTS_PATH + "/../..")

if not os.path.exists('src/.libs/libnftables.so'):
    print "The nftables library does not exist. " \
          "You need to build the project."
    sys.exit(1)

nftables = Nftables(sofile = 'src/.libs/libnftables.so')
nftables.set_echo_output(True)

# various commands to work with

flush_ruleset = { "flush": { "ruleset": None } }

add_table = { "add": {
    "table": {
        "family": "inet",
        "name": "t",
    }
}}

add_chain = { "add": {
    "chain": {
        "family": "inet",
        "table": "t",
        "name": "c"
    }
}}

add_set = { "add": {
    "set": {
        "family": "inet",
        "table": "t",
        "name": "s",
        "type": "inet_service"
    }
}}

add_rule = { "add": {
    "rule": {
        "family": "inet",
        "table": "t",
        "chain": "c",
        "expr": [ { "accept": None } ]
    }
}}

add_counter = { "add": {
    "counter": {
        "family": "inet",
        "table": "t",
        "name": "c"
    }
}}

add_quota = { "add": {
    "quota": {
        "family": "inet",
        "table": "t",
        "name": "q",
        "bytes": 65536
    }
}}

# helper functions

def exit_err(msg):
    print "Error: %s" % msg
    sys.exit(1)

def exit_dump(e, obj):
    print "FAIL: %s" % e
    print "Output was:"
    json.dumps(out, sort_keys = True, indent = 4, separators = (',', ': '))
    sys.exit(1)

def do_flush():
    rc, out, err = nftables.json_cmd({ "nftables": [flush_ruleset] })
    if not rc is 0:
        exit_err("flush ruleset failed: %s" % err)

def do_command(cmd):
    if not type(cmd) is list:
        cmd = [cmd]
    rc, out, err = nftables.json_cmd({ "nftables": cmd })
    if not rc is 0:
        exit_err("command failed: %s" % err)
    return out

# single commands first

do_flush()

print "Adding table t"
out = do_command(add_table)
try:
    table_out = out["nftables"][0]
    table_handle = out["nftables"][0]["add"]["table"]["handle"]
except Exception as e:
    exit_dump(e, out)

print "Adding chain c"
out = do_command(add_chain)
try:
    chain_out = out["nftables"][0]
    chain_handle = out["nftables"][0]["add"]["chain"]["handle"]
except Exception as e:
    exit_dump(e, out)

print "Adding set s"
out = do_command(add_set)
try:
    set_out = out["nftables"][0]
    set_handle = out["nftables"][0]["add"]["set"]["handle"]
except Exception as e:
    exit_dump(e, out)

print "Adding rule"
out = do_command(add_rule)
try:
    rule_out = out["nftables"][0]
    rule_handle = out["nftables"][0]["add"]["rule"]["handle"]
except Exception as e:
    exit_dump(e, out)

print "Adding counter"
out = do_command(add_counter)
try:
    counter_out = out["nftables"][0]
    counter_handle = out["nftables"][0]["add"]["counter"]["handle"]
except Exception as e:
    exit_dump(e, out)

print "Adding quota"
out = do_command(add_quota)
try:
    quota_out = out["nftables"][0]
    quota_handle = out["nftables"][0]["add"]["quota"]["handle"]
except Exception as e:
    exit_dump(e, out)

# adjust names and add items again
# Note: Add second chain to same table, otherwise it's handle will be the same
# as before. Same for the set and the rule. Bug?

table_out["add"]["table"]["name"] = "t2"
#chain_out["add"]["chain"]["table"] = "t2"
chain_out["add"]["chain"]["name"] = "c2"
#set_out["add"]["set"]["table"] = "t2"
set_out["add"]["set"]["name"] = "s2"
#rule_out["add"]["rule"]["table"] = "t2"
#rule_out["add"]["rule"]["chain"] = "c2"
counter_out["add"]["counter"]["name"] = "c2"
quota_out["add"]["quota"]["name"] = "q2"

print "Adding table t2"
out = do_command(table_out)
if out["nftables"][0]["add"]["table"]["handle"] == table_handle:
   exit_err("handle not changed in re-added table!")

print "Adding chain c2"
out = do_command(chain_out)
if out["nftables"][0]["add"]["chain"]["handle"] == chain_handle:
   exit_err("handle not changed in re-added chain!")

print "Adding set s2"
out = do_command(set_out)
if out["nftables"][0]["add"]["set"]["handle"] == set_handle:
   exit_err("handle not changed in re-added set!")

print "Adding rule again"
out = do_command(rule_out)
if out["nftables"][0]["add"]["rule"]["handle"] == rule_handle:
   exit_err("handle not changed in re-added rule!")

print "Adding counter c2"
out = do_command(counter_out)
if out["nftables"][0]["add"]["counter"]["handle"] == counter_handle:
   exit_err("handle not changed in re-added counter!")

print "Adding quota q2"
out = do_command(quota_out)
if out["nftables"][0]["add"]["quota"]["handle"] == quota_handle:
   exit_err("handle not changed in re-added quota!")

# now multiple commands

do_flush()

print "doing multi add"
add_multi = [ add_table, add_chain, add_set, add_rule ]
out = do_command(add_multi)
out = out["nftables"]

if not "handle" in out[0]["add"]["table"] or \
   not "handle" in out[1]["add"]["chain"] or \
   not "handle" in out[2]["add"]["set"] or \
   not "handle" in out[3]["add"]["rule"]:
       exit_err("handle(s) missing in multi cmd output!")
