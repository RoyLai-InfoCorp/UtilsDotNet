using System;
using System.Linq;

namespace UtilsDotNet.Extensions
{
	public static class UInt16Extensions
	{
		public static byte[] ToBytes(this UInt16 uint16, bool isBigEndian)
		{
			if (isBigEndian)
				return BitConverter.GetBytes(uint16);
			return BitConverter.GetBytes(uint16).Reverse().ToArray();
		}

	}
}
