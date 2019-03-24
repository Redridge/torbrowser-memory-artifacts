import os
import sys
import tqdm
import struct


# mapping start -> binary contents
mappings = {}
mappings_keys = []

document_string = "\x23\x00\x64\x00\x6f\x00\x63\x00\x75\x00\x6d\x00\x65\x00\x6e\x00\x74\x00"


def get_map_and_offset(addr):
	for i in range(len(mappings_keys)):
		if addr < mappings_keys[i]:
			return mappings_keys[i-1], addr - mappings_keys[i-1]

def find_file(_map):
	return filter(lambda x: _map in x, os.listdir("."))[0]

def read_vma_files(_dir):
	global mappings
	global mappings_keys

	files = os.listdir(_dir)
	for fl in tqdm.tqdm(files):
		map_start = int(fl.split(".")[2], 0)
		f = open(os.path.join(_dir, fl), "rb").read()
		mappings[map_start] = f
	mappings_keys = mappings.keys()
	mappings_keys.sort()

def find_in_map(_map, s):
	raw = mappings[_map]
	results = []
	pos = raw.find(s, 0)
	while pos != -1:
		results.append(pos)
		prev_pos = pos
		pos = raw.find(s, prev_pos + 1)
	return results

def find_in_all(s):
	results = []
	for _map in mappings_keys:
		r = find_in_map(_map, s)
		if r:
			results.append((_map, r))
	return results

def read_from_map(_map, offset, count):
	raw = mappings[_map]
	return raw[offset:offset+count]

def readuntil_from_map(_map, offset, c):
	raw = mappings[_map]
	end = raw.find(c, offset)
	return raw[offset:end]


if __name__ == "__main__":

	if len(sys.argv) != 2:
		print "Usage: {} <dumps_dir>".format(sys.argv[0])
		exit(1)
	dump_dir = sys.argv[1]

	# Read all vma files in memory for speed
	read_vma_files(dump_dir)

	# look for the "#document" string
	res = find_in_all(document_string)

	doc_str_addrs = []
	for _map, rs in res:
		for r in rs:
			doc_str_addrs.append(_map + r)
			#print hex(_map + r)
	if doc_str_addrs:
		print "#document string found at:"
		for r in doc_str_addrs:
			print "\t", hex(r)
	else:
		print "#document string not found"
		exit(1)
			
	# Recover Document object
	nodeinfo_refcnt_off = -9*8
	document_doctype_off = 2*8
	document_addrs = []
	for addr in doc_str_addrs:
		res = find_in_all(struct.pack("<Q", addr))
		for _map, rs in res:
			for r in rs:
				_bytes = read_from_map(_map, r + nodeinfo_refcnt_off, 8)
				refcnt = struct.unpack("<Q", _bytes)[0]
				if refcnt > 0 and refcnt < 0x100:
					_bytes = read_from_map(_map, r + nodeinfo_refcnt_off + 8, 8)
					document_addr = struct.unpack("<Q", _bytes)[0]
					
					__map, __off = get_map_and_offset(document_addr)
					_bytes = read_from_map(__map, __off + document_doctype_off, 8)
					doctype = struct.unpack("<Q", _bytes)[0]

					__map, __off = get_map_and_offset(doctype)
					_bytes = read_from_map(__map, __off, 8)
					doctype_ = struct.unpack("<Q", _bytes)[0]

					__map, __off = get_map_and_offset(doctype_)
					_bytes = read_from_map(__map, __off, 8)
					doctype__ = struct.unpack("<Q", _bytes)[0]

					__map, __off = get_map_and_offset(doctype__)
					_bytes = read_from_map(__map, __off, 8)
					doctype___ = struct.unpack("<Q", _bytes)[0]

					__map, __off = get_map_and_offset(doctype___)
					_bytes = read_from_map(__map, __off, 12)

					if _bytes == "HTMLDocument":
						document_addrs.append(document_addr)
	
	document_addrs = list(set(document_addrs))
	print
	print "MediaDocument found at:"
	for doc in document_addrs:
		print "\t", hex(doc)
	
	# Keep just 1st addr (prototype)
	document_addr = document_addrs[0]

	# Get URI
	document_docuri_off = 224
	docuri_string_off = 64
	__map, __off = get_map_and_offset(document_addr)
	_bytes = read_from_map(__map, __off + document_docuri_off, 8)
	docuri_addr = struct.unpack("<Q", _bytes)[0]

	__map, __off = get_map_and_offset(docuri_addr)
	_bytes = read_from_map(__map, __off + docuri_string_off, 8)
	docuri_str_addr = struct.unpack("<Q", _bytes)[0]

	__map, __off = get_map_and_offset(docuri_str_addr)
	document_uri = readuntil_from_map(__map, __off, '\x00')

	print
	print "DocumentURI: ", document_uri

	document_oriuri_off = 224 + 8
	oriuri_string_off = 64
	__map, __off = get_map_and_offset(document_addr)
	_bytes = read_from_map(__map, __off + document_oriuri_off, 8)
	oriuri_addr = struct.unpack("<Q", _bytes)[0]

	__map, __off = get_map_and_offset(oriuri_addr)
	_bytes = read_from_map(__map, __off + oriuri_string_off, 8)
	oriuri_str_addr = struct.unpack("<Q", _bytes)[0]

	__map, __off = get_map_and_offset(oriuri_str_addr)
	original_uri = readuntil_from_map(__map, __off, '\x00')

	print
	print "OriginalURI: ", original_uri
