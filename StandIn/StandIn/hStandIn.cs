using System;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Text;

namespace StandIn
{
	class hStandIn
	{
		[StructLayout(LayoutKind.Sequential)]
		public struct SearchObject
		{
			public Boolean success;
			public String sDC;
			public DirectorySearcher searcher;
		}

        public enum AccessRequest : UInt32
        {
            none,
            genericall,
            genericwrite,
            resetpassword,
            writemembers,
            dcsync
        }

        [Flags]
        public enum SUPPORTED_ETYPE : Int32
        {
            RC4_HMAC_DEFAULT = 0x0,
            DES_CBC_CRC = 0x1,
            DES_CBC_MD5 = 0x2,
            RC4_HMAC = 0x4,
            AES128_CTS_HMAC_SHA1_96 = 0x08,
            AES256_CTS_HMAC_SHA1_96 = 0x10
        }

        [Flags]
        public enum USER_ACCOUNT_CONTROL : Int32
        {
            SCRIPT = 0x00000001,
            ACCOUNTDISABLE = 0x00000002,
            HOMEDIR_REQUIRED = 0x00000008,
            LOCKOUT = 0x00000010,
            PASSWD_NOTREQD = 0x00000020,
            PASSWD_CANT_CHANGE = 0x00000040,
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
            TEMP_DUPLICATE_ACCOUNT = 0x00000100,
            NORMAL_ACCOUNT = 0x00000200,
            INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
            WORKSTATION_TRUST_ACCOUNT = 0x00001000,
            SERVER_TRUST_ACCOUNT = 0x00002000,
            UNUSED1 = 0x00004000,
            UNUSED2 = 0x00008000,
            DONT_EXPIRE_PASSWD = 0x00010000,
            MNS_LOGON_ACCOUNT = 0x00020000,
            SMARTCARD_REQUIRED = 0x00040000,
            TRUSTED_FOR_DELEGATION = 0x00080000,
            NOT_DELEGATED = 0x00100000,
            USE_DES_KEY_ONLY = 0x00200000,
            DONT_REQUIRE_PREAUTH = 0x00400000,
            PASSWORD_EXPIRED = 0x00800000,
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
            PARTIAL_SECRETS_ACCOUNT = 0x04000000,
            USE_AES_KEYS = 0x08000000
        }

        [Flags]
        public enum SAM_ACCOUNT_TYPE : Int32
        {
            SAM_DOMAIN_OBJECT = 0x0,
            SAM_GROUP_OBJECT = 0x10000000,
            SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001,
            SAM_ALIAS_OBJECT = 0x20000000,
            SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001,
            SAM_USER_OBJECT = 0x30000000,
            SAM_NORMAL_USER_ACCOUNT = 0x30000000,
            SAM_MACHINE_ACCOUNT = 0x30000001,
            SAM_TRUST_ACCOUNT = 0x30000002,
            SAM_APP_BASIC_GROUP = 0x40000000,
            SAM_APP_QUERY_GROUP = 0x40000001,
            SAM_ACCOUNT_TYPE_MAX = 0x7fffffff
        }

        public static void getHelp()
		{
			Console.WriteLine(@"  __               ");
			Console.WriteLine(@" ( _/_   _//   ~b33f");
			Console.WriteLine(@"__)/(//)(/(/)  v0.8");
            Console.WriteLine(@"");
            string HelpText = "\n >--~~--> Args? <--~~--<\n\n" +
							  "--help        This help menu\n" +
                              "--object      LDAP filter, e.g. samaccountname=HWest\n" +
                              "--computer    Machine name, e.g. Celephais-01\n" +
                              "--group       Group name, e.g. \"Necronomicon Admins\"\n" +
                              "--ntaccount   User name, e.g. \"REDHOOK\\UPickman\"\n" +
                              "--sid         String SID representing a target machine\n" +
                              "--grant       User name, e.g. \"REDHOOK\\KMason\"\n" +
                              "--guid        Rights GUID to add to object, e.g. 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\n" +
                              "--domain      Domain name, e.g. REDHOOK\n" +
							  "--user        User name\n" +
							  "--pass        Password\n" +
                              "--newpass     New password to set for object\n" +
                              "--type        Rights type: GenericAll, GenericWrite, ResetPassword, WriteMembers, DCSync\n" +
                              "--spn         Boolean, list kerberoastable accounts\n" +
                              "--delegation  Boolean, list accounts with unconstrained / constrained delegation\n" +
                              "--asrep       Boolean, list ASREP roastable accounts\n" +
                              "--dc          Boolean, list all domain controllers\n" +
                              "--remove      Boolean, remove msDS-AllowedToActOnBehalfOfOtherIdentity property from machine object\n" +
							  "--make        Boolean, make machine; ms-DS-MachineAccountQuota applies\n" +
							  "--disable     Boolean, disable machine; should be the same user that created the machine\n" +
                              "--access      Boolean, list access permissions for object\n" +
                              "--delete      Boolean, delete machine from AD; requires elevated AD access\n\n" +
							  " >--~~--> Usage? <--~~--<\n\n" +
							  "# Query object properties by LDAP filter\n" +
                              "StandIn.exe --object \"(&(samAccountType=805306368)(servicePrincipalName=*vermismysteriis.redhook.local*))\"\n" +
                              "StandIn.exe --object samaccountname=Celephais-01$ --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Query object access permissions, optionally filter by NTAccount\n" +
                              "StandIn.exe --object \"distinguishedname=DC=redhook,DC=local\" --access\n" +
                              "StandIn.exe --object samaccountname=Rllyeh$ --access --ntaccount \"REDHOOK\\EDerby\"\n" +
                              "StandIn.exe --object samaccountname=JCurwen --access --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Grant object access permissions\n" +
                              "StandIn.exe --object \"distinguishedname=DC=redhook,DC=local\" --grant \"REDHOOK\\MBWillett\" --type DCSync\n" +
                              "StandIn.exe --object \"distinguishedname=DC=redhook,DC=local\" --grant \"REDHOOK\\MBWillett\" --guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\n" +
                              "StandIn.exe --object samaccountname=SomeTarget001$ --grant \"REDHOOK\\MBWillett\" --type GenericWrite --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Set object password\n" +
                              "StandIn.exe --object samaccountname=SomeTarget001$ --newpass \"Arkh4mW1tch!\"\n" +
                              "StandIn.exe --object samaccountname=BJenkin --newpass \"Dr34m1nTh3H#u$e\" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add ASREP to userAccountControl flags\n" +
                              "StandIn.exe --object samaccountname=HArmitage --asrep\n" +
                              "StandIn.exe --object samaccountname=FMorgan --asrep --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Remove ASREP from userAccountControl flags\n" +
                              "StandIn.exe --object samaccountname=TMalone --asrep --remove\n" +
                              "StandIn.exe --object samaccountname=RSuydam --asrep  --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Get a list of all ASREP roastable accounts\n" +
                              "StandIn.exe --asrep\n" +
                              "StandIn.exe --asrep --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Get a list of all kerberoastable accounts\n" +
                              "StandIn.exe --spn\n" +
                              "StandIn.exe --spn --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# List all accounts with unconstrained & constrained delegation privileges\n" +
                              "StandIn.exe --delegation\n" +
                              "StandIn.exe --delegation --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Get a list of all domain controllers\n" +
                              "StandIn.exe --dc\n\n" +

                              "# List group members\n" +
                              "StandIn.exe --group Literarum\n" +
                              "StandIn.exe --group \"Magna Ultima\" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add user to group\n" +
                              "StandIn.exe --group \"Dunwich Council\" --ntaccount \"REDHOOK\\WWhateley\"\n" +
                              "StandIn.exe --group DAgon --ntaccount \"REDHOOK\\RCarter\" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Create machine object\n" +
                              "StandIn.exe --computer Innsmouth --make\n" +
                              "StandIn.exe --computer Innsmouth --make --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

							  "# Disable machine object\n" +
                              "StandIn.exe --computer Arkham --disable\n" +
                              "StandIn.exe --computer Arkham --disable --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

							  "# Delete machine object\n" +
                              "StandIn.exe --computer Danvers --delete\n" +
                              "StandIn.exe --computer Danvers --delete --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

							  "# Add msDS-AllowedToActOnBehalfOfOtherIdentity to machine object properties\n" +
                              "StandIn.exe --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543\n" +
                              "StandIn.exe --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543 --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

							  "# Remove msDS-AllowedToActOnBehalfOfOtherIdentity from machine object properties\n" +
                              "StandIn.exe --computer Miskatonic --remove\n" +
                              "StandIn.exe --computer Miskatonic --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e";
			Console.WriteLine(HelpText);
		}

        public static void printColor(String sText, ConsoleColor eColor)
        {
            Console.ForegroundColor = eColor;
            Console.WriteLine(sText);
            Console.ResetColor();
        }

		public static String genAccountPass()
		{
			String sKeyspace = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			Char[] sPass = new Char[15];
			Random rand = new Random();
			for (int i = 0; i < sPass.Length; i++)
			{
				sPass[i] = sKeyspace[rand.Next(sKeyspace.Length)];
			}

			return new string(sPass);
		}

        public static SearchObject createSearchObject(String sDomain = "", String sUser = "", String sPass = "", Boolean ActOnBehalf = false)
        {
            DirectoryEntry de = null;
            DirectorySearcher ds = null;
            SearchObject resultObject = new SearchObject();
            try
            {
                de = new DirectoryEntry();
                resultObject.sDC = de.Options.GetCurrentServerName();
                Console.WriteLine("\n[?] Using DC : " + de.Options.GetCurrentServerName());
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    String sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    de.Username = sUserDomain;
                    de.Password = sPass;
                }

                ds = new DirectorySearcher(de);
                if (ActOnBehalf)
                {
                    ds.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");
                }
                ds.PageSize = 1000;

                resultObject.success = true;
                resultObject.searcher = ds;
            }
            catch
            {
                resultObject.success = false;
            }

            return resultObject;
        }

        public static String rightsGUIDToFriendlyName(Guid rightsGuid, String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                DirectoryEntry rootdse = null;
                DirectoryEntry extendedRightsRoot = null;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    String sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    rootdse = new DirectoryEntry("LDAP://RootDSE", sUserDomain, sPass);
                    extendedRightsRoot = new DirectoryEntry("LDAP://" + rootdse.Properties["configurationNamingContext"].Value.ToString(), sUserDomain, sPass);
                }
                else
                {
                    rootdse = new DirectoryEntry("LDAP://RootDSE");
                    extendedRightsRoot = new DirectoryEntry("LDAP://CN=Extended-Rights," + rootdse.Properties["configurationNamingContext"].Value.ToString());
                }

                // Search
                DirectorySearcher ds = new DirectorySearcher(extendedRightsRoot);
                ds.SearchScope = System.DirectoryServices.SearchScope.OneLevel;
                ds.PropertiesToLoad.Add("cn");
                ds.Filter = $"(rightsGuid={rightsGuid.ToString("D")})";
                SearchResult sr = ds.FindOne();

                if (sr != null)
                {
                    return sr.Properties["cn"][0].ToString();
                }
                else
                {
                    return String.Empty;
                }
            }
            catch
            {
                return String.Empty;
            }
        }

        public static String schemaGUIDToFriendlyName(Guid schemaIDGuid, String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                DirectoryEntry rootdse = null;
                DirectoryEntry schemaRoot = null;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    String sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    rootdse = new DirectoryEntry("LDAP://RootDSE", sUserDomain, sPass);
                    schemaRoot = new DirectoryEntry("LDAP://" + rootdse.Properties["schemaNamingContext"].Value.ToString(), sUserDomain, sPass);
                }
                else
                {
                    rootdse = new DirectoryEntry("LDAP://RootDSE");
                    schemaRoot = new DirectoryEntry("LDAP://" + rootdse.Properties["schemaNamingContext"].Value.ToString());
                }

                // Search
                DirectorySearcher ds = new DirectorySearcher(schemaRoot);
                ds.SearchScope = System.DirectoryServices.SearchScope.OneLevel;
                ds.PropertiesToLoad.Add("ldapDisplayName");
                ds.Filter = $"(schemaIDGUID={hStandIn.BuildFilterOctetString(schemaIDGuid.ToByteArray())})";
                SearchResult sr = ds.FindOne();

                if (sr != null)
                {
                    return sr.Properties["ldapDisplayName"][0].ToString();
                }
                else
                {
                    return String.Empty;
                }
            }
            catch
            {
                return String.Empty;
            }
        }

        public static String BuildFilterOctetString(byte[] bytes)
		{
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.Length; i++)
			{
				sb.AppendFormat("\\{0}", bytes[i].ToString("X2"));
			}
			return sb.ToString();
		}
	}
}
