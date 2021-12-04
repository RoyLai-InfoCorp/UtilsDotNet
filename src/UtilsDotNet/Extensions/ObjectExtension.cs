// SPDX-FileCopyrightText: 2020-2021 InfoCorp Technologies Pte. Ltd. <roy.lai@infocorp.io>
// SPDX-License-Identifier: See LICENSE.txt

using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using System;
using System.IO;

namespace UtilsDotNet.Extensions
{
	public static class ObjectExtensions
	{
		public static string ToJson(this object obj)
		{
			return JsonConvert.SerializeObject(obj,
				Formatting.Indented,
				new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
		}

		public static byte[] Object2Bytes<T>(this T item)
		{
			byte[] bytes = null;
			if (item is string)
			{
				string s = (string)Convert.ChangeType(item, typeof(string));
				bytes = s.UTF82Bytes();
			}
			else if (item is int)
			{
				bytes = BitConverter.GetBytes((int)Convert.ChangeType(item, typeof(int)));
			}
			else
			{
				MemoryStream ms = new MemoryStream();
				using (BsonWriter bw = new BsonWriter(ms))
				{
					JsonSerializer js = new JsonSerializer();
					js.Serialize(bw, item);
				}
				bytes = ms.ToArray();
			}
			return bytes;
		}

	}
}
