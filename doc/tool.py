#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import tqdm
import struct

# mapping start -> binary contents

mappings = {}
mappings_keys = []

document_string = \
    "\x23\x00\x64\x00\x6f\x00\x63\x00\x75\x00\x6d\x00\x65\x00\x6e\x00\x74\x00"

element_list = []

element_nodeinfo_off = 4 * 8
element_parent_off = 5 * 8
element_ns_off = 6 * 8  # Next sibling
element_ps_off = 7 * 8  # Previous sibling
element_fc_off = 8 * 8  # First child
nodeinfo_qn_off = 9 * 8  # Qualified name
text_str_off = 12 * 8
a_uri_off = 136
video_uri_off = 384
img_uri_off = 272
docuri_string_off = 64


def get_map_and_offset(addr):
    for i in range(len(mappings_keys)):
        if addr < mappings_keys[i]:
            return (mappings_keys[i - 1], addr - mappings_keys[i - 1])
    return (0, 0)


def find_file(_map):
    return filter(lambda x: _map in x, os.listdir('.'))[0]


def read_vma_files(_dir):
    global mappings
    global mappings_keys

    files = os.listdir(_dir)
    for fl in tqdm.tqdm(files):
        map_start = int(fl.split('.')[2], 0)
        f = open(os.path.join(_dir, fl), 'rb').read()
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
    return raw[offset:offset + count]


def readuntil_from_map(_map, offset, c):
    raw = mappings[_map]
    end = raw.find(c, offset)
    return raw[offset:end]


class Element:

    def __init__(self, parent, addr):
        self.parent = parent
        self.addr = addr
        self.first_child = None
        self.next_sibling = None
        self.previous_sibling = None
        self.node_info = None
        self.node_info_ptrs = ()  # Name pointers
        self.node_info_strs = ()  # (QualifiedName, NodeName, LocalName)
        self.next = None
        self.child = None
        self.content = None

    def parse_element(self):
        (_map, _off) = get_map_and_offset(self.addr)
        _bytes = read_from_map(_map, _off + element_nodeinfo_off, 5 * 8)

        (self.node_info, parent, self.next_sibling,
         self.previous_sibling, self.first_child) = \
            struct.unpack('<QQQQQ', _bytes)
        assert parent == self.parent

        (_map, _off) = get_map_and_offset(self.node_info)
        _bytes = read_from_map(_map, _off + nodeinfo_qn_off, 6 * 8)
        node_info_ptrs = struct.unpack('<QQQQQQ', _bytes)
        self.node_info_ptrs = (node_info_ptrs[0], node_info_ptrs[2],
                               node_info_ptrs[4])
        sizes = (node_info_ptrs[1], node_info_ptrs[3],
                 node_info_ptrs[5])

        (_map, _off) = get_map_and_offset(self.node_info_ptrs[0])
        _bytes = read_from_map(_map, _off, (sizes[0] & 0xffffffff) * 2)
        qn_str = _bytes.replace('\x00', '')

        (_map, _off) = get_map_and_offset(self.node_info_ptrs[1])
        _bytes = read_from_map(_map, _off, (sizes[1] & 0xffffffff) * 2)
        nn_str = _bytes.replace('\x00', '')

        (_map, _off) = get_map_and_offset(self.node_info_ptrs[2])
        _bytes = read_from_map(_map, _off, (sizes[2] & 0xffffffff) * 2)
        ln_str = _bytes.replace('\x00', '')

        self.node_info_strs = (qn_str, nn_str, ln_str)

        # Parse #text nodes

        if self.node_info_strs[0] in ['#text', '#comment']:
            (_map, _off) = get_map_and_offset(self.addr)
            _bytes = read_from_map(_map, _off + text_str_off, 8 + 4)
            (str_ptr, size) = struct.unpack('<QI', _bytes)
            size = size / 8

            (_map, _off) = get_map_and_offset(str_ptr)
            _bytes = read_from_map(_map, _off, size)
            self.content = _bytes

        # Parse 'a' nodes

        if self.node_info_strs[0] == 'a':
            (_map, _off) = get_map_and_offset(self.addr)
            _bytes = read_from_map(_map, _off + a_uri_off, 8)
            uri_ptr = struct.unpack('<Q', _bytes)[0]

            if uri_ptr == 0:
                return
            (_map, _off) = get_map_and_offset(uri_ptr)
            _bytes = read_from_map(_map, _off + docuri_string_off, 8
                                   + 4)
            (str_ptr, size) = struct.unpack('<QI', _bytes)

            (_map, _off) = get_map_and_offset(str_ptr)
            if _map != 0:
                _bytes = read_from_map(_map, _off, size)
                self.content = _bytes

        # Parse 'video' nodes

        if self.node_info_strs[0] == 'video':
            (_map, _off) = get_map_and_offset(self.addr)
            _bytes = read_from_map(_map, _off + video_uri_off, 8)
            uri_ptr = struct.unpack('<Q', _bytes)[0]

            if uri_ptr == 0:
                return
            (_map, _off) = get_map_and_offset(uri_ptr)
            _bytes = read_from_map(_map, _off + docuri_string_off, 8
                                   + 4)
            (str_ptr, size) = struct.unpack('<QI', _bytes)

            (_map, _off) = get_map_and_offset(str_ptr)
            if _map != 0:
                _bytes = read_from_map(_map, _off, size)
                self.content = _bytes

        # Parse 'img' nodes

        if self.node_info_strs[0] == 'img':
            (_map, _off) = get_map_and_offset(self.addr)
            _bytes = read_from_map(_map, _off + img_uri_off, 8)
            uri_ptr = struct.unpack('<Q', _bytes)[0]

            if uri_ptr == 0:
                return
            (_map, _off) = get_map_and_offset(uri_ptr)
            _bytes = read_from_map(_map, _off + docuri_string_off, 8
                                   + 4)
            (str_ptr, size) = struct.unpack('<QI', _bytes)

            (_map, _off) = get_map_and_offset(str_ptr)
            if _map != 0:
                _bytes = read_from_map(_map, _off, size)
                self.content = _bytes

    def __str__(self):
        if self.content is None:
            return '[{}] element at {}'.format(self.node_info_strs,
                    hex(self.addr))
        return '[{}] element at {} --> {}'.format(self.node_info_strs,
                hex(self.addr), self.content)


def save_next(root, f):
    if root.child:
        save_html_to_file(root.child, f)
    if root.next:
        save_html_to_file(root.next, f)


def save_html_to_file(root, f):
    if root.content == None:
        root.content = ''
    if root.node_info_strs[0] == '#document':
        save_next(root, f)
    if root.node_info_strs[0] == '#text':
        f.write(root.content)
        save_next(root, f)
    elif root.node_info_strs[0] == '#comment':
        f.write('<!-- ' + root.content + ' -->')
        save_next(root, f)
    elif root.node_info_strs[0] == 'a':
        f.write('<a href="' + root.content + '">')
        save_next(root, f)
        f.write('</a>')
    elif root.node_info_strs[0] == 'video':
        f.write('<video src="' + root.content + '">')
        save_next(root, f)
        f.write('</video>')
    elif root.node_info_strs[0] == 'img':
        f.write('<img src="' + root.content + '">')
        save_next(root, f)
        f.write('</img>')
    else:
        f.write('<' + root.node_info_strs[0] + '>')
        save_next(root, f)
        f.write('</' + root.node_info_strs[0] + '>')


def parse_elements(root):
    if root.first_child:
        child_el = Element(root.addr, root.first_child)
        child_el.parse_element()
        element_list.append(child_el)
        root.child = child_el
        parse_elements(child_el)
    if root.next_sibling:
        sibling_el = Element(root.parent, root.next_sibling)
        sibling_el.parse_element()
        element_list.append(sibling_el)
        root.next = sibling_el
        parse_elements(sibling_el)


def print_elements(root):
    print root
    if root.first_child:
        print_elements(root.child)
    if root.next_sibling:
        print_elements(root.next)


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print 'Usage: {} <dumps_dir>'.format(sys.argv[0])
        exit(1)
    dump_dir = sys.argv[1]

    # Read all vma files in memory for speed

    read_vma_files(dump_dir)

    # look for the "#document" string

    res = find_in_all(document_string)

    doc_str_addrs = []
    for (_map, rs) in res:
        for r in rs:
            doc_str_addrs.append(_map + r)

            # print hex(_map + r)

    if doc_str_addrs:
        print '#document string found at:'
        for r in doc_str_addrs:
            print '\t', hex(r)
    else:
        print '#document string not found'
        exit(1)

    # Recover Document object

    nodeinfo_refcnt_off = -9 * 8
    document_doctype_off = 2 * 8
    document_addrs = []
    for addr in doc_str_addrs:
        res = find_in_all(struct.pack('<Q', addr))
        for (_map, rs) in res:
            for r in rs:
                _bytes = read_from_map(_map, r + nodeinfo_refcnt_off, 8)
                refcnt = struct.unpack('<Q', _bytes)[0]
                if refcnt > 0 and refcnt < 0x100:
                    _bytes = read_from_map(_map, r
                            + nodeinfo_refcnt_off + 8, 8)
                    document_addr = struct.unpack('<Q', _bytes)[0]

                    (__map, __off) = get_map_and_offset(document_addr)
                    _bytes = read_from_map(__map, __off
                            + document_doctype_off, 8)
                    doctype = struct.unpack('<Q', _bytes)[0]

                    (__map, __off) = get_map_and_offset(doctype)
                    _bytes = read_from_map(__map, __off, 8)
                    doctype_ = struct.unpack('<Q', _bytes)[0]

                    (__map, __off) = get_map_and_offset(doctype_)
                    _bytes = read_from_map(__map, __off, 8)
                    doctype__ = struct.unpack('<Q', _bytes)[0]

                    (__map, __off) = get_map_and_offset(doctype__)
                    _bytes = read_from_map(__map, __off, 8)
                    doctype___ = struct.unpack('<Q', _bytes)[0]

                    (__map, __off) = get_map_and_offset(doctype___)
                    _bytes = read_from_map(__map, __off, 12)

                    if _bytes == 'HTMLDocument':
                        document_addrs.append(document_addr)

    document_addrs = list(set(document_addrs))
    print
    print 'MediaDocument found at:'
    for doc in document_addrs:
        print '\t', hex(doc)

    # Keep just 1st addr (prototype)

    document_addr = document_addrs[0]

    # Get URI

    document_docuri_off = 224
    (__map, __off) = get_map_and_offset(document_addr)
    _bytes = read_from_map(__map, __off + document_docuri_off, 8)
    docuri_addr = struct.unpack('<Q', _bytes)[0]

    (__map, __off) = get_map_and_offset(docuri_addr)
    _bytes = read_from_map(__map, __off + docuri_string_off, 8)
    docuri_str_addr = struct.unpack('<Q', _bytes)[0]

    (__map, __off) = get_map_and_offset(docuri_str_addr)
    document_uri = readuntil_from_map(__map, __off, '\x00')

    print
    print 'DocumentURI: ', document_uri

    document_oriuri_off = 224 + 8
    oriuri_string_off = 64
    (__map, __off) = get_map_and_offset(document_addr)
    _bytes = read_from_map(__map, __off + document_oriuri_off, 8)
    oriuri_addr = struct.unpack('<Q', _bytes)[0]

    (__map, __off) = get_map_and_offset(oriuri_addr)
    _bytes = read_from_map(__map, __off + oriuri_string_off, 8)
    oriuri_str_addr = struct.unpack('<Q', _bytes)[0]

    (__map, __off) = get_map_and_offset(oriuri_str_addr)
    original_uri = readuntil_from_map(__map, __off, '\x00')

    print
    print 'OriginalURI: ', original_uri

    document_referrer_off = 192
    (__map, __off) = get_map_and_offset(document_addr)
    _bytes = read_from_map(__map, __off + document_referrer_off, 8 + 4)
    (str_ptr, size) = struct.unpack('<QI', _bytes)

    (_map, _off) = get_map_and_offset(str_ptr)
    if _map != 0:
        _bytes = read_from_map(_map, _off, size)
        referrer = _bytes
    else:
        referrer = ''
    print
    print 'Referrer: ', referrer

    # Get DOM Tree Objects using DFS

    document_el = Element(0, document_addr)
    document_el.parse_element()
    element_list.append(document_el)
    parse_elements(document_el)

    # print_elements(document_el)
    # print len(element_list)

    with open('dump.html', 'w') as dump:
        save_html_to_file(document_el, dump)


			
