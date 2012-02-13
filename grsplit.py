#!/usr/bin/env python

# -*- coding: utf-8 -*-

import codecs
import re
import argparse
import shutil
import os
import sys

__authors__     = ["Fabiano Francesconi <fabiano dot francesconi at gmail dot com>"]
__license__     =  "MIT"
__copyright__   =  "Copyright 2012, Fabiano Francesconi"
__status__      =  "Development"
__version__     =  "0.1"

def parse_file(filepath, rolespath, includepath, suppress_backup):
	f = codecs.open(filepath, encoding="utf-8")

	currentrole = None
	rolebuffer = ""
	mainbuffer = ""
	for line in f:
		role = parse_line(line)
		if role:
			# If we hit a new role, dump the previous one
			if (currentrole != None):
				dump_role(rolebuffer, rolespath, currentrole)

				# Add the include line
				mainbuffer += get_include_line(includepath, currentrole)

			currentrole = role
			rolebuffer = ""
		else:
			if (currentrole == None):
				mainbuffer += line
		rolebuffer += line

	# When the file is over it means that we have the last role to dump
	dump_role(rolebuffer, rolespath, currentrole)
	# Add the include line
	mainbuffer += get_include_line(includepath, currentrole)
	
	# Generate the backup file
	if not suppress_backup:
		create_backup(filepath)

	# Dump the new policy file
	dump_buffer(mainbuffer, filepath)

def parse_line(line):
	m = re.match("^role (\w+) u.*?$", line)
	if m:
		return m.group(1)
	return None

def dump_buffer(rolebuffer, filename):
	f = codecs.open(filename, "w", encoding="utf-8")
	f.write(rolebuffer)
	f.close()

def dump_role(rolebuffer, rolespath, rolename):
	sys.stdout.write("Dumping role '{}'\n".format(rolename))
	fname = rolespath + rolename
	dump_buffer(rolebuffer, fname)

def get_include_line(includepath, rolename):
	include_line = "include <" + includepath + rolename + ">\n"
	return include_line

def create_backup(filename):
	shutil.copyfile(filename, filename + ".bck")

def validate_input(args):
	""" Validate the input given by the user """
	if not os.path.isfile(args.policy):
		die("Policy file does not exist.")

	if not os.path.isdir(args.directory):
		die("Directory argument '{}' does not exist.".format(os.path.abspath(args.directory)))

# ----------

def die(s):
  """Exits on fatal errors."""
  sys.stderr.write("[ERROR] {}\n".format(s))
  sys.exit(1)

# ----------

opt_parser = argparse.ArgumentParser(description='a policy splitter for Grsecurity RBAC policies.')
opt_parser.add_argument('policy', type=str, help='policy file to be modified')
opt_parser.add_argument('-d', '--directory', default="/etc/grsec/roles", help='use existing DIRECTORY as the directory to write files in (default: "/etc/grsec/roles")')
opt_parser.add_argument('-i', '--include-path', default="/etc/grsec/roles", help='path used in main policy file when including external policy files. (default: "/etc/grsec/roles")')
opt_parser.add_argument('-b', '--suppress-backup', action='store_true', default=False, help='suppress backup file creation. (default: false)')
opt_parser.add_argument('-v', '--version', action='version', version='%(prog)s-'+__version__)

args = opt_parser.parse_args()

# Validate input
validate_input(args)

# Normalize paths
rolespath = os.path.abspath(args.directory) + os.sep
includepath = os.path.abspath(args.include_path) + os.sep

# Do the dirty job
parse_file(args.policy, rolespath, includepath, args.suppress_backup)
