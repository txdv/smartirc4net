using System;
using System.Collections.Generic;
using Manos.IO;

namespace Meebey.SmartIrc4net
{
    public class CallbackCollection : IEnumerable<ByteBuffer>
    {
        protected List<Tuple<ByteBuffer, Action>> elements = new List<Tuple<ByteBuffer, Action>>();

        public CallbackCollection()
        {
        }

        public void Add(byte[] data, Action action)
        {
            Add(new ByteBuffer(data, 0, data.Length), action);
        }

        public void Add(ByteBuffer data, Action action)
        {
            elements.Add(Tuple.Create(data, action));
        }

        #region IEnumerable[ByteBuffer] implementation
        public IEnumerator<ByteBuffer> GetEnumerator()
        {
            foreach (var element in elements) {
                element.Item2();
                yield return element.Item1;
            }
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return (System.Collections.IEnumerator)this.GetEnumerator();
        }
        #endregion
    }
}

