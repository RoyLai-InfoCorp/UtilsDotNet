using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace UtilsDotNet.Extensions
{
	public static class ByteArrayExtensions
	{
		public static byte[] Keccak256(this byte[] bytes)
		{
			var digest = new KeccakDigest(256);
			digest.BlockUpdate(bytes, 0, bytes.Length);
			var calculatedHash = new byte[digest.GetByteLength()];
			digest.DoFinal(calculatedHash, 0);
			return calculatedHash.Take(32).ToArray();
		}

		public static T Bytes2Object<T>(this byte[] bytes)
		{
			var ms = new MemoryStream(bytes);
			T result = default(T);
			if (typeof(T) == typeof(string))
			{
				var s = Encoding.UTF8.GetString(bytes, 0, bytes.Length);
				result = (T)Convert.ChangeType(s, typeof(T));
			}
			else if (typeof(T) == typeof(int))
			{
				result = (T)Convert.ChangeType(BitConverter.ToInt32(bytes, 0), typeof(T));
			}
			else
			{
				using (BsonReader br = new BsonReader(ms))
				{
					JsonSerializer js = new JsonSerializer();
					result = js.Deserialize<T>(br);
				}
			}
			return result;
		}

		public static BigInteger Bytes2BigInteger(this byte[] bytes, bool isUnsigned = true, bool isBigEndian = true)
		{
			return new BigInteger(bytes, isUnsigned, isBigEndian);
		}

		public static UInt16 Bytes2UInt16(this byte[] bytes, bool isBigEndian = false)
		{
			if (BitConverter.IsLittleEndian && isBigEndian || !BitConverter.IsLittleEndian && !isBigEndian)
				return BitConverter.ToUInt16(bytes.Reverse().ToArray());
			return BitConverter.ToUInt16(bytes.ToArray());
		}


		public static byte[] SHA256(this byte[] bytes)
		{
			return CryptoHelper.SHA256(bytes);
		}

		public static byte[] RIPEMD160(this byte[] bytes)
		{
			return CryptoHelper.RIPEMD160(bytes);
		}


		public static byte[] XOR(this byte[] bytes1, byte[] bytes2)
		{
			if (bytes1.Length != bytes2.Length)
				throw new Exception("XOR cannot run on different length strings.");
			var clone = (byte[])bytes1.Clone();
			for (int i = 0; i < clone.Length; i++)
			{
				clone[i] = (byte)(clone[i] ^ bytes2[i]);
			}
			return clone;
		}

		public static bool IsZeros(this byte[] array)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));

			int count = 0;
			while (count < array.Length)
			{
				if (array[count] > 0)
					return false;
				count++;
			}
			return true;
		}

		public static byte[] SafeSubarray(this byte[] array, int offset, int count)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));
			if (offset < 0 || offset > array.Length)
				throw new ArgumentOutOfRangeException(nameof(offset));
			if (count < 0 || offset + count > array.Length)
				throw new ArgumentOutOfRangeException(nameof(count));
			if (offset == 0 && array.Length == count)
				return array;
			var data = new byte[count];
			Buffer.BlockCopy(array, offset, data, 0, count);
			return data;
		}

		public static byte[] SafeSubarray(this byte[] array, int offset)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));
			if (offset < 0 || offset > array.Length)
				throw new ArgumentOutOfRangeException(nameof(offset));

			var count = array.Length - offset;
			var data = new byte[count];
			Buffer.BlockCopy(array, offset, data, 0, count);
			return data;
		}


		/// <summary>
		/// Replace a segment of bytes in the byte array with a new array of bytes
		/// </summary>
		/// <param name="src"></param>
		/// <param name="srcOffset"></param>
		/// <param name="srcCount"></param>
		/// <param name="substitution"></param>
		/// <returns></returns>
		public static byte[] BlockReplace(this byte[] src, UInt32 srcOffset, UInt32 srcCount, byte[] substitution)
		{
			var buffer = new byte[src.Length - srcCount + substitution.Length];

			Buffer.BlockCopy(src, 0, buffer, 0, src.Length);
			Buffer.BlockCopy(substitution, 0, buffer, (int)srcOffset, substitution.Length);
			Buffer.BlockCopy(src, (int)(srcOffset + srcCount), buffer, (int)srcOffset + substitution.Length, src.Length - (int)(srcOffset + srcCount));

			return buffer;
		}




		/// <summary>
		/// Convert bytes to hexadecimal binary encoding
		/// </summary>
		/// <param name="bytes"></param>
		/// <returns></returns>
		public static string Bytes2Hex(this byte[] bytes)
		{
			if (bytes != null)
				return BitConverter.ToString(bytes).ToLower().Replace("-", "");
			return null;
		}

		/// <summary>
		/// Convert bytes to 2-byte integer
		/// </summary>
		/// <param name="b"></param>
		/// <returns></returns>
		public static short Bytes2Int16(this byte[] bytes)
		{
			if (bytes.Length > 2)
				throw new Exception("Invalid byte size for Int16.");
			return BitConverter.ToInt16(bytes, 0);
		}

		/// <summary>
		/// Convert bytes to 4-byte integer
		/// </summary>
		/// <param name="b"></param>
		/// <returns></returns>
		public static int Bytes2Int32(this byte[] bytes)
		{
			if (bytes.Length > 4)
				throw new Exception("Invalid byte size for Int32.");
			return BitConverter.ToInt32(bytes, 0);
		}

		/// <summary>
		/// Convert bytes to 8-byte integer
		/// </summary>
		/// <param name="b"></param>
		/// <returns></returns>
		public static Int64 Bytes2Int64(this byte[] bytes)
		{
			if (bytes.Length > 8)
				throw new Exception("Invalid byte size for Int64.");
			return BitConverter.ToInt64(bytes, 0);
		}

		/// <summary>
		/// Convert bytes to UTF8 text encoding
		/// </summary>
		/// <returns></returns>
		public static string Bytes2UTF8(this byte[] bytes)
		{
			return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
		}

		/// <summary>
		/// Convert bytes to Base64 binary encoding
		/// </summary>
		/// <returns></returns>
		public static string Bytes2Base64(this byte[] bytes)
		{
			return Convert.ToBase64String(bytes);
		}

		/// <summary>
		/// Convert bytes to Base58 binary encoding
		/// </summary>
		/// <returns></returns>
		public static string Bytes2Base58(this byte[] bytes)
		{
			return SimpleBase.Base58.Bitcoin.Encode(bytes);
		}


		public static byte[] CombineAndCopy(this byte[] first, byte[] second)
		{
			byte[] ret = new byte[first.Length + second.Length];
			Buffer.BlockCopy(first, 0, ret, 0, first.Length);
			Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
			return ret;
		}
	}
}
