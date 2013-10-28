#
# Copyright (c) 2011-2013 RightScale Inc
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

require 'rubygems'

begin

  # attempt to early-load basic Windows API gems so that we can rescue and
  # switch to using the simple definition of File.normalize_path when these gems
  # are unavailable.
  require ::File.expand_path('../../../../platform', __FILE__)

  class File

    # Expand the path then shorten the directory, if possible.
    # Only shortens the parent directory and not the leaf (file or directory)
    # name because 'gem' wants the file name to be long for require.
    #
    # @param [String] file_name to normalize
    # @param [String] dir_string as base directory path for relative file_name
    #   or ignored when file_name is absolute (Default = working directory).
    #
    # @return [String] normalized path
    def self.normalize_path(file_name, *dir_string)
      path = self.expand_path(file_name, *dir_string)
      dir = ::RightScale::Platform.filesystem.long_path_to_short_path(self.dirname(path))
      self.join(dir, self.basename(path))
    end
  end

rescue LoadError

  # use the simple definition of normalize_path on load error. the purpose of
  # normalize_path is to disambiguate load paths but it is possible to continue
  # with ambiguity in most cases and any other Win32 API calls will fail.
  class File
    def self.normalize_path(file_name, *dir_string)
      self.expand_path(file_name, *dir_string)
    end
  end
end
