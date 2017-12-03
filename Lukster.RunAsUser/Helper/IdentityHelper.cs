using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Lukster.RunAsUser.Helper
{
	/// <summary>
	/// Enum that is used to specify what part of the identity name should be used or returned.
	/// </summary>
	public enum IdentityPart
	{
		Domainname,
		Username
	}

    /// <summary>
    /// 
    /// </summary>
	public class IdentityHelper
	{
		/// <summary>
		/// Returns a part of the Windows specific user account string representation that is of form:
		/// &lt;domainname&gt;\&lt;username&gt; using the Name property of the IIdentity object.
		/// </summary>
		/// <param name="identity">The IIdentity object</param>
		/// <param name="part">The enumeration of the IdentityPart enumeration class</param>
		/// <returns>Either the domain name or the username as specified</returns>
		private static readonly string REGEX_IDENTITYNAME = @"((?<domain>\w*)\\)?(?<username>.*)";
		public static string GetIdentityPart(string identity, IdentityPart part)
		{
			if (identity == null)
				throw new ArgumentNullException();
			if (!Enum.IsDefined(typeof(IdentityPart), part))
				throw new ArgumentException("part");

			string chosenOption = string.Empty;
			switch (part)
			{
				case IdentityPart.Domainname:
					chosenOption = "domain";
					break;
				case IdentityPart.Username:
					chosenOption = "username";
					break;
				default:
					throw new InvalidOperationException(string.Format("IdentityPart {0} not implemented.", part));
			}
			// perform regex match
			Match m = Regex.Match(identity, REGEX_IDENTITYNAME);
			// if match was successful then return result..otherwise return empty string to avoid NullReferenceExceptions
			if (m.Success)
				return m.Groups[chosenOption].Value;
			else
				return string.Empty;
		}
	}
}
