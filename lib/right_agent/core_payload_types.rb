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
#

CORE_PAYLOAD_TYPES_BASE_DIR = File.join(File.dirname(__FILE__), 'core_payload_types')

require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'cookbook'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'cookbook_repository'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'cookbook_sequence'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'cookbook_position'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'dev_repository'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'dev_repositories'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'executable_bundle'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'event_categories'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'recipe_instantiation'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'repositories_bundle'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'software_repository_instantiation'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'right_script_attachment'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'right_script_instantiation'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'login_policy'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'login_user'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'runlist_policy'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'secure_document'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'secure_document_location'))
require File.normalize_path(File.join(CORE_PAYLOAD_TYPES_BASE_DIR, 'planned_volume'))
