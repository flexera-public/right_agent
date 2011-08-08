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

# Scans the 'usage' for a given file and returns the resulting String.
#
# Note : no formatting occurs. Rdoc is nice as is.
#

module Usage

  # Scans the given file from its usage (the top comment block) and
  # returns it
  #
  # === Parameters
  # file(String)::
  #   path to file to read
  #
  # === Return
  # String::
  #   the usage as found in the file
  #
  def self.scan(file)

    lines = File.readlines(file)  # Display usage from the given file
    result = []

    while line = lines.shift
      if m = line.match(/^ *#(.*)$/)
        result << m[1]
      else
        break unless result.empty?
      end
    end

    result.join("\n")
  end

end

