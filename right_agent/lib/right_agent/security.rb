#
# Copyright (c) 2009-2011 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

SECURITY_BASE_DIR = File.join(File.dirname(__FILE__), 'security')

require File.normalize_path(File.join(SECURITY_BASE_DIR, 'cached_certificate_store_proxy'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'certificate'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'certificate_cache'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'distinguished_name'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'encrypted_document'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'rsa_key_pair'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'signature'))
require File.normalize_path(File.join(SECURITY_BASE_DIR, 'static_certificate_store'))
