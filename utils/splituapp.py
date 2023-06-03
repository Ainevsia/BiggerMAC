# https://github.com/superr/splituapp
# splituapp for Python2/3 by SuperR. @XDA
#
# For extracting img files from UPDATE.APP

# Based on the app_structure file in split_updata.pl by McSpoon

import os
import sys
import string
import struct

def extract(source: str, flist = None):

	bytenum = 4
	outdir = os.path.join(os.path.dirname(source), 'output')
	if os.path.exists(outdir):
		print('Output directory already exists')
		return 1
	img_files = []
	
	try:
		os.makedirs(outdir)
	except:
		pass

	with open(source, 'rb') as f:
		while True:
			i = f.read(bytenum)
			if not i:
				break
			elif i != b'\x55\xAA\x5A\xA5':
				continue
			headersize = f.read(bytenum)
			headersize = list(struct.unpack('<L', headersize))[0]
			f.seek(16, 1)
			filesize = f.read(bytenum)
			filesize = list(struct.unpack('<L', filesize))[0]
			f.seek(32, 1)
			filename = f.read(16)

			try:
				filename = str(filename.decode())
				filename = ''.join(f for f in filename if f in string.printable).lower()
			except:
				filename = ''

			f.seek(22, 1)

			if not flist or filename in flist:
				if filename in img_files:
					filename = filename+'_2'

				print('Extracting '+filename+'.img ...')

				chunk = 10240

				try:
					with open(outdir+os.sep+filename+'.img', 'wb') as o:
						while filesize > 0:
							if chunk > filesize:
								chunk = filesize

							o.write(f.read(chunk))
							filesize -= chunk
				except:
					print('ERROR: Failed to create '+filename+'.img\n')
					return 1

				img_files.append(filename)

			else:
				f.seek(filesize, 1)

			xbytes = bytenum - f.tell() % bytenum
			if xbytes < bytenum:
				f.seek(xbytes, 1)

	print('\nExtraction complete')
	return 0
