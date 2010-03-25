/////////////////////////////////////////////////////////////////////////
// Copyright (c) 2010 RightScale Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
/////////////////////////////////////////////////////////////////////////
using System;
using System.Collections;

namespace RightScale
{
    namespace Chef
    {
        namespace Protocol
        {
            // data for a set-ChefNode request
            public class SetChefNodeRequest
            {
                public string[] Path
                {
                    get { return path; }
                    set { path = value; }
                }

                public object NodeValue
                {
                    get { return nodeValue; }
                    set { nodeValue = value; }
                }

                public SetChefNodeRequest()
                {
                }

                public SetChefNodeRequest(ICollection path, object nodeValue)
                {
                    this.path = new string[path.Count];

                    int index = 0;
                    foreach (object element in path)
                    {
                        this.path[index++] = element.ToString();
                    }
                    this.nodeValue = nodeValue;
                }

                public override string ToString()
                {
                    object value = nodeValue;

                    if (null == nodeValue)
                    {
                        value = "NULL";
                    }
                    else if (nodeValue is String)
                    {
                        value = "\"" + nodeValue + "\"";
                    }

                    return String.Format("SetChefNodeRequest: SET {{ Path = node[{0}], NodeValue = {1} }}", String.Join("][", path), value);
                }

                private string[] path;
                private object nodeValue;
            }
        }
    }
}
