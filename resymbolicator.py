# -*- coding: utf-8 -*
#!/usr/bin/python

import json
import argparse
import os.path
import re

class UUIDChecker:
	def __init__(self, appName):
		self.appName = appName

	def get_crashlog_uuid(self, crashTxt):

		#crashTxt = "0x104fbc000 - 0x10c31ffff WePop arm64  <84769a611f8d3e369b621d4cee8cd4cd> /var/"
		rexStr = r"Binary Images:\s.+" + self.appName + r".+[<](\w+)[>]"
		print "[crashlog uuid rexStr]" + rexStr

		pattern = re.compile(rexStr)
		match = re.search(pattern, crashTxt)

		if match:
			uuid = match.group(1)
			print "crash log uuid:" + uuid

			return uuid
		else:
			print "crash log uuid NOT FOUND"
			return None

	def get_dSYM_uuid(self, dsymPath):
		output = os.popen('xcrun dwarfdump --uuid ' + dsymPath, 'r')
		result = output.read()
		print result

		uuidArr = result.splitlines()
		arm64 = uuidArr[1]

		segs = arm64.split()
		uuid = segs[1].lower().replace('-', '')

		print uuid

		return uuid

	def check(self, dsymPath, crashTxt):
		logUUID = self.get_crashlog_uuid(crashTxt)
		dsymUUID = self.get_dSYM_uuid(dsymPath)

		return logUUID == dsymUUID

class Resymbolicator:
	def __init__(self, appName, dsymPath):
		self.appName = appName
		patternStr = appName + r"\s+(\w+) (\w+)"
		self.pattern = re.compile(patternStr)
		self.dsymPath = dsymPath

	def is_app_stack(self, lineStr):
		if (lineStr.find(self.appName) > 0 and lineStr.find("0x") > 0):
			return True
		else:
			return False

	def get_line_meta(self, lineStr):

		match = re.search(self.pattern, lineStr)
		if (match):
			finalAddr = match.group(1)
			baseAddr = match.group(2)

			#int lineStr + " > " + finalAddr + "," + baseAddr

			return baseAddr, finalAddr

		return None, None

	def get_resymbol_str(self, baseAddr, finalAddr):

		cmd = "atos -o " + self.dsymPath + "/Contents/Resources/DWARF/" + self.appName + " -arch arm64 -l " + baseAddr + " " + finalAddr
		#print cmd
		output = os.popen(cmd, 'r')
		result = output.read()
		
		return result

	def resymbol(self, lines):

		for lnNum in range(0, len(lines)):
			lnStr = lines[lnNum]

			if (self.is_app_stack(lnStr)):
				baseAddr, finalAddr = self.get_line_meta(lnStr)

				if (baseAddr):
					convertedTxt = self.get_resymbol_str(baseAddr, finalAddr)
					lines[lnNum] = lnStr + " " + convertedTxt

		return lines


def main():
	parser = argparse.ArgumentParser(description='resymplicate ios crash file')
	parser.add_argument('dsymPath', help='dSYM file path')
	parser.add_argument('crashLogPath', help='crash log path')
	parser.add_argument('appName', help='app name, ex:"WePop.app.dSYM/Contents/Resources/DWARF/WePop", "WePop" is the app name')

	args = parser.parse_args()
	print args

	#check file exist
	# if (not os.path.isfile(args.dsymPath)):
	# 	print "dsym path not exist at path:" + args.dsymPath
	# 	return 1

	if (not os.path.isfile(args.crashLogPath)):
		print "crash log not exist at path:" + args.crashLogPath
		return 1

	outputPath = "resymbolicated.txt"

	with open(args.crashLogPath) as f:
		crashTxt = f.read()

		uuidChecker = UUIDChecker(args.appName)
		isUUIDSame = uuidChecker.check(args.dsymPath, crashTxt)

		if (not isUUIDSame):
			print "uuid not equal"
			return

		crashLines = crashTxt.splitlines()

		resym = Resymbolicator(args.appName, args.dsymPath)
		lines = resym.resymbol(crashLines)

		resultTxt = '\n'.join(lines)
		#print resultTxt

		with open(outputPath,'w') as outputFile:
			outputFile.write(resultTxt)

		print "success"


if __name__=="__main__":
	main()
	
