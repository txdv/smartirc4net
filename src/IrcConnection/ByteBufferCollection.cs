using System;
using System.Collections.Generic;
using System.Linq;

using Manos.IO;

namespace Meebey.SmartIrc4net
{
 public class ByteBufferCollection
 {
     private LinkedList<ByteBuffer> buffers = new LinkedList<ByteBuffer>();
     public ByteBufferCollection()
     {
     }

     public void AddCopy(byte[] bytes)
     {
         Add(bytes.Clone() as byte[]);
     }

     public void AddCopy(ByteBuffer buffer)
     {
         byte[] bytes = new byte[buffer.Length];
         Buffer.BlockCopy(buffer.Bytes, buffer.Position, bytes, 0, bytes.Length);
         Add(new ByteBuffer(bytes, 0, bytes.Length));
     }

     public void Add(byte[] bytes)
     {
         Add(new ByteBuffer(bytes));
     }

     public void Add(ByteBuffer buffer)
     {
         buffers.AddLast(buffer);
     }

     private IEnumerable<ByteBuffer> Enumerate()
     {
         for (var current = buffers.First; current != null; current = current.Next) {
             yield return current.Value;
         }
         yield break;
     }

     private IEnumerable<byte> EnumerateBytes()
     {
         return EnumerateBytes(0);
     }

     private IEnumerable<byte> EnumerateBytes(int skip)
     {
         bool skiped = skip == 0;
         foreach (var buffer in Enumerate()) {
             int i = 0;
             int pos = buffer.Position;
             if (!skiped) {
                 if (skip < buffer.Length) {
                     i = skip;
                     skiped = true;
                     yield return buffer.Bytes[i + pos];
                 } else {
                     skip -= buffer.Length;
                 }
             } else {
                 for (; i < buffer.Length; i++) {
                     yield return buffer.Bytes[i + pos];
                 }
             }
         }
         yield break;
     }

     public void Skip(int restLength)
     {
         foreach (var buffer in Enumerate()) {
             int r = restLength - buffer.Length;
             if (r >= 0) {
                 buffer.Skip(buffer.Length);
                 buffers.Remove(buffer);
                 restLength = r;
             } else {
                 // it is the last buffer we need to skip
                 // break afterwards
                 buffer.Skip(restLength);
                 return;
             }
         }
     }

     public bool HasLength(int length)
     {
         foreach (var buffer in buffers) {
             if (length < buffer.Length) {
                 return true;
             }
             length -= buffer.Length;
         }
         return false;
     }

     public int Length {
         get {
             int length = 0;
             foreach (var buffer in buffers) {
                 length += buffer.Length;
             }
             return length;
         }
     }

     public byte this[int index] {
         get {
             int position = index;
             foreach (var buffer in buffers) {
                 if (position < buffer.Length) {
                     return buffer.Bytes[buffer.Position + position];
                 } else {
                     position -= buffer.Length;
                 }
             }
             throw new Exception();
         }
     }

     public void CopyTo(byte[] destination, int length)
     {
         int startPos = 0;
         foreach (var buffer in buffers) {
             int rest = length - buffer.Length;
             if (rest <= 0) {
                 Buffer.BlockCopy(buffer.Bytes, buffer.Position, destination, startPos, length);
                 break;
             } else {
                 Buffer.BlockCopy(buffer.Bytes, buffer.Position, destination, startPos, buffer.Length);
                 startPos += buffer.Length;
                 length = rest;
             }
         }
     }

     public int FirstByte(byte val)
     {
         int pos = 0;
         foreach (var buffer in buffers) {
             for (int i = 0; i < buffer.Length; i++) {
                 if (buffer.Bytes[i + buffer.Position] == val) {
                     return pos;
                 } else {
                     pos++;
                 }
             }
         }
         return -1;
     }

     public int FirstBytes(byte[] bytes)
     {
         return FirstBytes(bytes, 0);
     }

     public int FirstBytes(byte[] bytes, int start)
     {
         if ((bytes == null) || (bytes.Length == 0)) {
             throw new ArgumentException("bytes cannot be equal null or have the length of 0");
         }

         int endPosition = bytes.Length - 1;

         if (endPosition == 0) {
             return FirstByte(bytes[0]);
         }

         bool started = false;
         int bytesPos = 0;
         int startPos = -1;

         int i = start;
         foreach (byte b in EnumerateBytes(start)) {
             if (started) {
                 if (bytesPos == endPosition) {
                     if (b == bytes[bytesPos]) {
                         return startPos;
                     } else {
                         return FirstBytes(bytes, startPos + 1);
                     }
                 } else {
                     if (b == bytes[bytesPos]) {
                         bytesPos++;
                     } else {
                         return FirstBytes(bytes, startPos + 1);
                     }
                 }
             } else {
                 if (b == bytes[0]) {
                     startPos = i;
                     bytesPos++;
                     started = true;
                 }
             }
             i++;
         }

         return -1;
     }

     public byte CurrentByte {
         get {
             var buffer = buffers.First();
             return buffer.CurrentByte;
         }
     }

     public bool ReadLong(int size, out long result)
     {
         if (size > sizeof(long) || !HasLength(size)) {
             result = 0;
             return false;
         }

         result = this[size - 1];

         for (int i = size - 2;i >= 0; i--) {
             result <<= 8;
             result |= this[i];
         }

         return true;
     }
 }
}
